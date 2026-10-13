//! Close, abandon, and sealing (design §4.6).
//!
//! - **Close** (one transaction, audited): lock the changeset, refuse it
//!   unless it is open, at the caller's `If-Match` version and not empty;
//!   translate every operation's snapshot into logical `args`
//!   ([`super::translate`]) and fill them (the one write an operation row
//!   ever gets); build the `attome-changeset/v1` document; checksum it (JCS,
//!   [`super::jcs`]) and hash its operations; mark it closed. The response
//!   carries the document, its plain-language summary ([`super::summary`])
//!   and the warnings: values translation left out, and entities the metadata
//!   change log shows changed since the changeset opened that no recorded
//!   operation covers (a D-025 crash window or a write that bypassed the
//!   recorder).
//! - **Abandon**: only an empty changeset (`attome_core::changeset::store`
//!   enforces it); the way out of an unwanted change is a further change in
//!   the same changeset, then close.
//! - **Sealing** an automatic changeset: the recorder inserts it already
//!   closed; its document and checksum are computed the first time it is
//!   shown or exported — the same translation without the refusals. Sealing
//!   writes derived data only and is idempotent under the row lock, so it
//!   runs on a read and writes no audit event of its own (the writes it
//!   describes were audited when they happened).

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_core::EngineState;
use attome_core::changeset::errors;
use attome_core::changeset::{ChangesetRow, ChangesetStatus, Layer, OperationRow, Seal, store};
use attome_types::AppError;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sqlx::PgConnection;
use utoipa::ToSchema;
use uuid::Uuid;

use super::{FORMAT, jcs, summary, translate};
use crate::bundle::PLATFORM_VERSION;

/// The most unrecorded-entity warnings one close reports.
const MAX_COVERAGE_WARNINGS: i64 = 100;

/// One close warning.
#[derive(Debug, Clone, Serialize, ToSchema, PartialEq, Eq)]
pub struct CloseWarning {
    /// `non_portable_value` (translation left a deployment-local id out) or
    /// `unrecorded_entity_change` (the metadata change log shows the entity
    /// changed after the changeset opened, and no recorded operation covers
    /// it).
    pub kind: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity: Option<String>,
}

/// What a sealed changeset is.
pub(crate) struct Built {
    pub(crate) seal: Seal,
    /// `(seq, args)` for every operation that has args.
    pub(crate) args: Vec<(i32, Value)>,
    pub(crate) warnings: Vec<CloseWarning>,
}

/// The close result.
pub(crate) struct Closed {
    pub(crate) row: ChangesetRow,
    pub(crate) summary: String,
    pub(crate) warnings: Vec<CloseWarning>,
}

fn timestamp(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Micros, true)
}

/// `requires` as the document carries it: the opener's `after`/`modules`
/// and a platform floor, this binary's version unless the opener set one.
fn document_requires(stored: &Value) -> Value {
    let mut out = Map::new();
    let stored = stored.as_object();
    let platform = stored
        .and_then(|r| r.get("platform"))
        .and_then(Value::as_str)
        .map_or_else(|| format!(">={PLATFORM_VERSION}"), str::to_owned);
    out.insert("platform".into(), Value::String(platform));
    for key in ["after", "modules"] {
        if let Some(value) = stored.and_then(|r| r.get(key))
            && value.as_array().is_some_and(|a| !a.is_empty())
        {
            out.insert(key.into(), value.clone());
        }
    }
    Value::Object(out)
}

/// The server's own number for a changeset in its `(layer, scope)` folder:
/// one more than the sealed changesets there. `write-closed.mjs` renumbers
/// it to the git folder's next number, so it only has to be in `1..=9999`.
async fn document_seq(conn: &mut PgConnection, row: &ChangesetRow) -> Result<i64, AppError> {
    let sealed: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM changeset \
         WHERE layer = $1 AND scope = $2 AND status = 'closed' AND checksum IS NOT NULL \
           AND id <> $3",
    )
    .bind(row.layer.as_str())
    .bind(&row.scope)
    .bind(row.id)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok((sealed + 1).clamp(1, 9999))
}

/// Translates every operation and builds the sealed document. Reads only.
pub(crate) async fn build(
    conn: &mut PgConnection,
    row: &ChangesetRow,
    ops: &[OperationRow],
    closed_at: DateTime<Utc>,
) -> Result<Built, AppError> {
    let mut operations = Vec::with_capacity(ops.len());
    let mut args_out = Vec::new();
    let mut warnings = Vec::new();
    for (index, op) in ops.iter().enumerate() {
        let expected = i32::try_from(index + 1).map_err(AppError::internal)?;
        if op.seq != expected {
            return Err(AppError::internal(format!(
                "changeset {}: operation seq {} where {expected} was expected",
                row.id, op.seq
            )));
        }
        let translated = translate::translate(conn, op).await?;
        warnings.extend(translated.warnings.into_iter().map(|message| CloseWarning {
            kind: "non_portable_value".into(),
            message,
            seq: Some(op.seq),
            entity: None,
        }));
        let mut entry = json!({
            "seq": op.seq,
            "op": op.op,
            "phase": op.phase,
            "target": op.target,
        });
        if let Some(args) = translated.args {
            if let Value::Object(map) = &mut entry {
                map.insert("args".into(), args.clone());
            }
            args_out.push((op.seq, args));
        }
        operations.push(entry);
    }
    let operations = Value::Array(operations);
    let ops_hash = jcs::sha256_tagged(
        jcs::canonicalize(&operations)
            .map_err(AppError::internal)?
            .as_bytes(),
    );

    let mut document = json!({
        "format": FORMAT,
        "id": row.id,
        "layer": row.layer.as_str(),
        "scope": row.scope,
        "seq": document_seq(conn, row).await?,
        "name": row.name,
        "title": row.title,
        "requires": document_requires(&row.requires),
        "author": row.author_label,
        "opened_at": timestamp(row.opened_at),
        "closed_at": timestamp(closed_at),
        "operations": operations,
    });
    if !row.description.is_empty()
        && let Value::Object(map) = &mut document
    {
        map.insert("description".into(), Value::String(row.description.clone()));
    }
    let checksum = jcs::document_checksum(&document).map_err(AppError::internal)?;
    if let Value::Object(map) = &mut document {
        map.insert("checksum".into(), Value::String(checksum.clone()));
    }
    Ok(Built {
        seal: Seal {
            document,
            checksum,
            ops_hash,
        },
        args: args_out,
        warnings,
    })
}

/// Entities the metadata change log shows changed after `row` opened that
/// no operation recorded since then (in any changeset) names.
async fn coverage_warnings(
    conn: &mut PgConnection,
    row: &ChangesetRow,
) -> Result<Vec<CloseWarning>, AppError> {
    let entities: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT l.logicalname \
         FROM metadata_change_log l \
         WHERE l.id > $1 AND l.logicalname IS NOT NULL \
           AND NOT EXISTS ( \
               SELECT 1 FROM changeset_operation o \
               WHERE o.recorded_at >= $2 \
                 AND (o.target ->> 'entity' = l.logicalname OR o.object_ref = l.entity_ref)) \
         ORDER BY 1 LIMIT $3",
    )
    .bind(row.opened_log_id)
    .bind(row.opened_at)
    .bind(MAX_COVERAGE_WARNINGS)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(entities
        .into_iter()
        .map(|entity| CloseWarning {
            kind: "unrecorded_entity_change".into(),
            message: format!(
                "the entity {entity:?} changed after this changeset was opened, but no recorded \
                 operation covers it; record the change again inside a changeset, or the \
                 promoted metadata will not include it"
            ),
            seq: None,
            entity: Some(entity),
        })
        .collect())
}

/// Closes an authored changeset (design §4.6) and writes its
/// `Configuration / Closed` security event in the same transaction.
pub(crate) async fn close(
    state: &EngineState,
    actor: Uuid,
    id: Uuid,
    expected_row_version: i64,
) -> Result<Closed, AppError> {
    let mut stx = SecurityTx::begin(
        state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Closed,
            actor,
            "changeset",
            Some(id),
        )
        .named("changeset.close"),
    )
    .await?;
    let tx = stx.tx();

    // The refusals come before any translation work.
    let row = store::lock(tx, id).await?.ok_or(AppError::NotFound)?;
    if row.status != ChangesetStatus::Open {
        return Err(AppError::Conflict(errors::CHANGESET_NOT_OPEN));
    }
    if row.row_version != expected_row_version {
        return Err(AppError::VersionConflict);
    }
    if row.op_count == 0 {
        return Err(AppError::Conflict(errors::CHANGESET_EMPTY));
    }

    // `now()` is the transaction's timestamp, so the document's `closed_at`
    // equals the column `store::close` writes.
    let closed_at: DateTime<Utc> = sqlx::query_scalar("SELECT now()")
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    let ops = store::operations(&mut **tx, id).await?;
    let built = build(tx, &row, &ops, closed_at).await?;
    for (seq, args) in &built.args {
        store::fill_args(tx, id, *seq, args).await?;
    }
    let closed = store::close(tx, id, Some(expected_row_version), &built.seal).await?;
    let mut warnings = built.warnings;
    warnings.extend(coverage_warnings(tx, &closed).await?);
    let summary = summary::summarize(&built.seal.document);
    stx.commit().await?;

    tracing::info!(
        changeset_id = %id,
        layer = closed.layer.as_str(),
        scope = %closed.scope,
        operations = closed.op_count,
        warnings = warnings.len(),
        "changeset closed"
    );
    Ok(Closed {
        row: closed,
        summary,
        warnings,
    })
}

/// Abandons an empty open changeset, writing its `Configuration / Cancelled`
/// security event in the same transaction.
pub(crate) async fn abandon(
    state: &EngineState,
    actor: Uuid,
    id: Uuid,
    expected_row_version: Option<i64>,
) -> Result<ChangesetRow, AppError> {
    let mut stx = SecurityTx::begin(
        state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Cancelled,
            actor,
            "changeset",
            Some(id),
        )
        .named("changeset.abandon"),
    )
    .await?;
    let row = store::abandon(stx.tx(), id, expected_row_version).await?;
    stx.commit().await?;
    tracing::info!(changeset_id = %id, "changeset abandoned");
    Ok(row)
}

/// Seals a closed automatic changeset that has no document yet and returns
/// the row as it now is; any other changeset is returned unchanged.
pub(crate) async fn seal_if_automatic(
    state: &EngineState,
    row: ChangesetRow,
) -> Result<ChangesetRow, AppError> {
    if !(row.origin.is_automatic() && row.status == ChangesetStatus::Closed)
        || row.document.is_some()
    {
        return Ok(row);
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let Some(locked) = store::lock(&mut tx, row.id).await? else {
        return Err(AppError::NotFound);
    };
    // Sealed by a concurrent reader while this one waited on the lock.
    if locked.document.is_some() || locked.op_count == 0 {
        attome_db::tx::commit(tx).await?;
        return Ok(locked);
    }
    let closed_at = locked.closed_at.unwrap_or(locked.updated_at);
    let ops = store::operations(&mut *tx, locked.id).await?;
    let built = build(&mut tx, &locked, &ops, closed_at).await?;
    for (seq, args) in &built.args {
        let unfilled = ops.iter().any(|o| o.seq == *seq && o.args.is_none());
        if unfilled {
            store::fill_args(&mut tx, locked.id, *seq, args).await?;
        }
    }
    let sealed = store::seal_automatic(&mut tx, locked.id, &built.seal).await?;
    let now = store::lock(&mut tx, locked.id)
        .await?
        .ok_or(AppError::NotFound)?;
    attome_db::tx::commit(tx).await?;
    if sealed {
        tracing::info!(changeset_id = %now.id, "automatic changeset sealed");
    }
    Ok(now)
}

/// The layers a changeset may be opened in through the admin API (the
/// customer layer is Phase 3).
pub(crate) fn authorable_layer(value: &str) -> Option<Layer> {
    Layer::parse(value).filter(|l| *l != Layer::Customer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_core::changeset::Origin;

    #[test]
    fn requires_keeps_after_and_modules_and_defaults_the_platform_floor() {
        assert_eq!(
            document_requires(&json!({})),
            json!({ "platform": format!(">={PLATFORM_VERSION}") })
        );
        assert_eq!(
            document_requires(&json!({
                "platform": ">=4.2.0",
                "after": ["platform/platform/0001-x"],
                "modules": [],
            })),
            json!({ "platform": ">=4.2.0", "after": ["platform/platform/0001-x"] })
        );
    }

    #[test]
    fn timestamps_are_utc_with_a_z() {
        let at = DateTime::parse_from_rfc3339("2026-09-29T10:20:00.123456Z")
            .expect("parse")
            .with_timezone(&Utc);
        assert_eq!(timestamp(at), "2026-09-29T10:20:00.123456Z");
    }

    #[test]
    fn only_platform_product_and_project_are_authorable() {
        assert_eq!(authorable_layer("project"), Some(Layer::Project));
        assert_eq!(authorable_layer("platform"), Some(Layer::Platform));
        assert_eq!(authorable_layer("customer"), None);
        assert_eq!(authorable_layer("tenant"), None);
        assert!(Origin::Auto.is_automatic());
    }
}
