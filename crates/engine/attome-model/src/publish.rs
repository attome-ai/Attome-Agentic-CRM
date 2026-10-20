//! Publishing (the minimal step before section 0.5's versions, Y8): an
//! object's open draft becomes its published version once the whole-version
//! checks pass, and the cooked runtime state is rebuilt from the published
//! store.
//!
//! The published set is every object's newest published version. On one
//! server (Solo) [`rebuild`] after a publish keeps the cooked registry
//! current; switching versions across several servers is Y8's.

use std::collections::BTreeSet;

use attome_db::DbPool;
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

use crate::KindRegistry;
use crate::cooker::{self, CookManifest};
use crate::identity::{KindName, ObjectId, ObjectRef};
use crate::kind::Kind;
use crate::validate::{CrossChecks, VersionObject, VersionSet, publish_error, validate_publish};

#[derive(sqlx::FromRow)]
struct DraftRow {
    version_no: i64,
    kind_schema_version: i32,
    doc: Value,
    name: String,
}

#[derive(sqlx::FromRow)]
struct PublishedRow {
    id: Uuid,
    kind: String,
    name: String,
    kind_schema_version: i32,
    doc: Value,
}

/// What [`publish`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    pub object_id: Uuid,
    pub version_no: i64,
}

/// Publishes the object's open draft, in the caller's transaction (which
/// commits it, with its audit event). Refuses when there is no draft, when
/// another save holds the object, or when the draft fails the publish checks
/// (a dangling reference, a kind check, a cross-object check).
pub async fn publish(
    tx: &mut attome_db::Tx<'_>,
    registry: &KindRegistry,
    cross: &CrossChecks,
    kind: &dyn Kind,
    object_id: Uuid,
) -> Result<Published, AppError> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-model/save:{object_id}"))
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "a metadata write is already in progress",
        ));
    }
    let draft: Option<DraftRow> = sqlx::query_as(
        "SELECT v.version_no, v.kind_schema_version, v.doc, o.name \
         FROM metadata_object_version v JOIN metadata_object o ON o.id = v.object_id \
         WHERE v.object_id = $1 AND v.state = 'draft' AND o.kind = $2 AND o.is_active",
    )
    .bind(object_id)
    .bind(kind.name().as_str())
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let DraftRow {
        version_no,
        kind_schema_version: schema_version,
        doc,
        name,
    } = draft.ok_or(AppError::NotFound)?;

    let refs = kind.references(&doc);
    let missing = crate::references::missing_targets(tx, registry, &refs).await?;
    let external: BTreeSet<ObjectRef> = refs
        .iter()
        .map(|r| r.target)
        .filter(|target| !missing.contains(target))
        .collect();
    let attribute_types = crate::validate::attribute_types(tx, registry, &external).await?;
    let set = VersionSet {
        objects: vec![VersionObject {
            kind: kind.name(),
            id: ObjectId(object_id),
            name,
            doc,
            schema_version: u32::try_from(schema_version).unwrap_or(0),
        }],
        external,
        attribute_types,
    };
    validate_publish(&set, registry, cross).map_err(|issues| publish_error(&issues))?;

    sqlx::query(
        "UPDATE metadata_object_version SET state = 'published' \
         WHERE object_id = $1 AND version_no = $2 AND state = 'draft'",
    )
    .bind(object_id)
    .bind(version_no)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    // A5-T1: an entity whose choice field uses this option set takes the new
    // values: its registry entry is re-read through the metadata change log.
    if kind.name() == crate::kinds::OPTION_SET {
        sqlx::query(
            "INSERT INTO metadata_change_log (entity_ref, logicalname, change_kind) \
             SELECT DISTINCT e.id, e.logicalname, 'upsert' \
             FROM attribute_info a JOIN entity_info e ON e.id = a.entity_ref \
             WHERE a.options->>'option_set' = $1 \
               AND (a.is_active IS NULL OR a.is_active) AND (e.is_active IS NULL OR e.is_active)",
        )
        .bind(&set.objects[0].name)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        // Y8-T1: ring the Postgres doorbell as `append_change_log` does
        // (`attome_core::METADATA_CHANGE_CHANNEL`; this crate sits below it).
        // The payload is unused: a listener reads the change log itself.
        sqlx::query("SELECT pg_notify('attome_metadata_change', '')")
            .execute(&mut **tx)
            .await
            .map_err(AppError::internal)?;
    }
    Ok(Published {
        object_id,
        version_no,
    })
}

/// The published set: every active object's newest published version, of a
/// kind this registry knows.
pub async fn published_set(pool: &DbPool, registry: &KindRegistry) -> Result<VersionSet, AppError> {
    let rows: Vec<PublishedRow> = sqlx::query_as(
        "SELECT DISTINCT ON (o.id) o.id, o.kind, o.name, v.kind_schema_version, v.doc \
         FROM metadata_object o JOIN metadata_object_version v ON v.object_id = o.id \
         WHERE o.is_active AND v.state = 'published' \
         ORDER BY o.id, v.version_no DESC",
    )
    .fetch_all(pool)
    .await
    .map_err(AppError::internal)?;
    let objects = rows
        .into_iter()
        .filter_map(|row| {
            let kind = registry.get(&row.kind)?;
            Some(VersionObject {
                kind: KindName(kind.name().as_str()),
                id: ObjectId(row.id),
                name: row.name,
                doc: row.doc,
                schema_version: u32::try_from(row.kind_schema_version).unwrap_or(0),
            })
        })
        .collect();
    Ok(VersionSet {
        objects,
        ..VersionSet::default()
    })
}

/// Cooks the published set (reusing `previous`'s unchanged artefacts),
/// stores the new artefacts and returns the manifest.
pub async fn cook_published(
    pool: &DbPool,
    registry: &KindRegistry,
    previous: Option<&CookManifest>,
) -> Result<CookManifest, AppError> {
    let set = published_set(pool, registry).await?;
    let cooked = cooker::cook(&set, previous, registry)?;
    cooker::write_artefacts(pool, &cooked.new_artefacts).await?;
    Ok(cooked.manifest)
}
