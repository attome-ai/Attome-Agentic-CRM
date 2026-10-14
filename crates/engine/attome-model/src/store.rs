//! The one versioned object store (roadmap Y1-T3): save a draft, read an
//! object at a version, list its history and diff two versions, for every
//! kind.
//!
//! Each object has at most one open draft (a partial unique index enforces
//! it); saving again replaces that draft's document. Saves of one object are
//! serialised with a transaction-scoped advisory lock keyed
//! `attome-model/save:{object_id}` (namespace [`crate::ADVISORY_LOCK_NAMESPACE`]);
//! a concurrent save gets `409` rather than waiting.
//!
//! The cooked registry (Y1-T7) follows changes through this store's own
//! version rows, not `metadata_change_log`: that log drives the entity
//! registry, whose consumer would read a form's id as an entity.

use attome_db::{DbPool, Tx};
use attome_types::{AppError, OnePageQuery, PaginatedResponse};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use crate::canonical::content_hash;
use crate::identity::{Layer, ObjectId};
use crate::kind::Kind;

/// The object a draft belongs to; created on its first save.
#[derive(Debug, Clone)]
pub struct ObjectSpec {
    pub id: ObjectId,
    /// Unique per kind and app.
    pub name: String,
    /// The app (pack) the object belongs to; `customer` for the customer's own.
    pub app: String,
    pub layer: Layer,
}

/// What [`save_draft`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftSaved {
    pub object_id: Uuid,
    pub version_no: i64,
    pub content_hash: String,
    /// `true` when this save opened the draft, `false` when it replaced it.
    pub opened: bool,
    /// References to objects that do not exist. They do not block the draft;
    /// publishing refuses them.
    pub issues: Vec<crate::kind::Issue>,
}

/// One version of one object.
#[derive(Debug, Clone, PartialEq, Serialize, sqlx::FromRow)]
pub struct ObjectVersion {
    pub object_id: Uuid,
    pub kind: String,
    pub name: String,
    pub version_no: i64,
    pub kind_schema_version: i32,
    pub state: String,
    pub doc: Value,
    pub content_hash: String,
    pub created_at: DateTime<Utc>,
}

/// One row of an object's history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow)]
pub struct VersionSummary {
    pub version_no: i64,
    pub state: String,
    pub content_hash: String,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// One RFC 6902 operation.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct JsonPatchOp {
    pub op: &'static str,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

/// Saves `doc` as the object's open draft, creating the object on its first
/// save. Runs inside the caller's transaction; the caller commits.
pub async fn save_draft(
    tx: &mut Tx<'_>,
    registry: &crate::KindRegistry,
    kind: &dyn Kind,
    object: &ObjectSpec,
    doc: &Value,
    actor: Option<Uuid>,
) -> Result<DraftSaved, AppError> {
    if let Err(issues) = kind.validate_shape(doc) {
        let text: Vec<String> = issues
            .iter()
            .map(|issue| format!("{} {}: {}", issue.path, issue.code, issue.message))
            .collect();
        return Err(AppError::Validation(text.join("; ")));
    }
    let hash = content_hash(doc).map_err(AppError::Validation)?;
    let size = crate::canonical::canonicalize(doc)
        .map_err(AppError::Validation)?
        .len();
    let limits = kind.limits();
    if size > limits.max_doc_bytes {
        return Err(AppError::Validation(format!(
            "a {} document is limited to {} bytes; this one is {size}",
            kind.name(),
            limits.max_doc_bytes
        )));
    }

    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-model/save:{}", object.id))
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "a metadata write is already in progress",
        ));
    }

    let existing_kind: Option<String> =
        sqlx::query_scalar("SELECT kind FROM metadata_object WHERE id = $1")
            .bind(object.id.0)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::internal)?;
    match existing_kind {
        Some(found) if found != kind.name().as_str() => {
            return Err(AppError::Conflict("this object id belongs to another kind"));
        }
        Some(_) => {}
        None => {
            // Y1-T11: the kind's object limit, checked when one is created.
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM metadata_object WHERE kind = $1 AND is_active",
            )
            .bind(kind.name().as_str())
            .fetch_one(&mut **tx)
            .await
            .map_err(AppError::internal)?;
            if usize::try_from(count).unwrap_or(usize::MAX) >= limits.max_objects {
                return Err(AppError::Validation(format!(
                    "a deployment may hold at most {} {} objects",
                    limits.max_objects,
                    kind.name()
                )));
            }
            sqlx::query(
                "INSERT INTO metadata_object (id, kind, name, app, owner_layer) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(object.id.0)
            .bind(kind.name().as_str())
            .bind(&object.name)
            .bind(&object.app)
            .bind(object.layer.as_str())
            .execute(&mut **tx)
            .await
            .map_err(|error| {
                if attome_db::is_unique_violation(&error) {
                    AppError::Conflict(
                        "a metadata object of this kind with this name already exists",
                    )
                } else {
                    AppError::internal(error)
                }
            })?;
        }
    }

    let draft: Option<i64> = sqlx::query_scalar(
        "SELECT version_no FROM metadata_object_version WHERE object_id = $1 AND state = 'draft'",
    )
    .bind(object.id.0)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let schema_version = i32::try_from(kind.schema_version()).unwrap_or(i32::MAX);
    let (version_no, opened) = match draft {
        Some(version_no) => {
            sqlx::query(
                "UPDATE metadata_object_version \
                 SET doc = $3, content_hash = $4, kind_schema_version = $5, created_by = $6, \
                     created_at = now() \
                 WHERE object_id = $1 AND version_no = $2 AND state = 'draft'",
            )
            .bind(object.id.0)
            .bind(version_no)
            .bind(doc)
            .bind(&hash)
            .bind(schema_version)
            .bind(actor)
            .execute(&mut **tx)
            .await
            .map_err(AppError::internal)?;
            (version_no, false)
        }
        None => {
            let version_no: i64 = sqlx::query_scalar(
                "INSERT INTO metadata_object_version \
                 (object_id, version_no, kind_schema_version, doc, content_hash, state, created_by) \
                 SELECT $1, COALESCE(MAX(version_no), 0) + 1, $2, $3, $4, 'draft', $5 \
                 FROM metadata_object_version WHERE object_id = $1 \
                 RETURNING version_no",
            )
            .bind(object.id.0)
            .bind(schema_version)
            .bind(doc)
            .bind(&hash)
            .bind(actor)
            .fetch_one(&mut **tx)
            .await
            .map_err(AppError::internal)?;
            (version_no, true)
        }
    };
    // The reference graph follows the draft, in the same transaction.
    let refs = kind.references(doc);
    let source = crate::identity::ObjectRef {
        kind: kind.name(),
        id: object.id,
    };
    crate::references::replace_references(tx, &source, &refs).await?;
    let issues = crate::references::dangling(tx, registry, &refs).await?;
    Ok(DraftSaved {
        object_id: object.id.0,
        version_no,
        content_hash: hash,
        opened,
        issues,
    })
}

/// The object at `at`, or at its newest version (draft included) when `at`
/// is `None`.
pub async fn read(
    pool: &DbPool,
    object_id: Uuid,
    at: Option<i64>,
) -> Result<ObjectVersion, AppError> {
    let row: Option<ObjectVersion> = sqlx::query_as(
        "SELECT o.id AS object_id, o.kind, o.name, v.version_no, v.kind_schema_version, v.state, \
                v.doc, v.content_hash, v.created_at \
         FROM metadata_object o \
         JOIN metadata_object_version v ON v.object_id = o.id \
         WHERE o.id = $1 AND o.is_active AND ($2::bigint IS NULL OR v.version_no = $2) \
         ORDER BY v.version_no DESC \
         LIMIT 1",
    )
    .bind(object_id)
    .bind(at)
    .fetch_optional(pool)
    .await
    .map_err(AppError::internal)?;
    row.ok_or(AppError::NotFound)
}

/// One object in a kind's listing: its newest version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow)]
pub struct ObjectSummary {
    pub id: Uuid,
    pub name: String,
    pub app: String,
    pub owner_layer: String,
    pub version_no: i64,
    pub state: String,
    pub content_hash: String,
}

/// The active objects of one kind, by name.
pub async fn list_objects(
    pool: &DbPool,
    kind: &str,
    page: &OnePageQuery,
) -> Result<PaginatedResponse<ObjectSummary>, AppError> {
    let window = page.window();
    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM metadata_object WHERE kind = $1 AND is_active")
            .bind(kind)
            .fetch_one(pool)
            .await
            .map_err(AppError::internal)?;
    let items: Vec<ObjectSummary> = sqlx::query_as(
        "SELECT o.id, o.name, o.app, o.owner_layer, v.version_no, v.state, v.content_hash \
         FROM metadata_object o \
         JOIN LATERAL ( \
             SELECT version_no, state, content_hash FROM metadata_object_version \
             WHERE object_id = o.id ORDER BY version_no DESC LIMIT 1 \
         ) v ON TRUE \
         WHERE o.kind = $1 AND o.is_active \
         ORDER BY o.name, o.id LIMIT $2 OFFSET $3",
    )
    .bind(kind)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(pool)
    .await
    .map_err(AppError::internal)?;
    Ok(PaginatedResponse {
        items,
        total,
        page: window.page,
        page_size: window.page_size,
    })
}

/// The object's versions, newest first.
pub async fn history(
    pool: &DbPool,
    object_id: Uuid,
    page: &OnePageQuery,
) -> Result<PaginatedResponse<VersionSummary>, AppError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM metadata_object WHERE id = $1 AND is_active)",
    )
    .bind(object_id)
    .fetch_one(pool)
    .await
    .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }
    let window = page.window();
    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM metadata_object_version WHERE object_id = $1")
            .bind(object_id)
            .fetch_one(pool)
            .await
            .map_err(AppError::internal)?;
    let items: Vec<VersionSummary> = sqlx::query_as(
        "SELECT version_no, state, content_hash, created_by, created_at \
         FROM metadata_object_version WHERE object_id = $1 \
         ORDER BY version_no DESC LIMIT $2 OFFSET $3",
    )
    .bind(object_id)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(pool)
    .await
    .map_err(AppError::internal)?;
    Ok(PaginatedResponse {
        items,
        total,
        page: window.page,
        page_size: window.page_size,
    })
}

/// The RFC 6902 operations that turn version `from` into version `to`.
pub async fn diff(
    pool: &DbPool,
    object_id: Uuid,
    from: i64,
    to: i64,
) -> Result<Vec<JsonPatchOp>, AppError> {
    let before = read(pool, object_id, Some(from)).await?;
    let after = read(pool, object_id, Some(to)).await?;
    Ok(json_diff(&before.doc, &after.doc))
}

fn pointer_segment(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// RFC 6902 operations from `before` to `after`: objects member by member,
/// arrays index by index (extra elements added or removed at the end), and
/// anything else replaced whole.
pub fn json_diff(before: &Value, after: &Value) -> Vec<JsonPatchOp> {
    let mut ops = Vec::new();
    diff_at(String::new(), before, after, &mut ops);
    ops
}

fn diff_at(path: String, before: &Value, after: &Value, ops: &mut Vec<JsonPatchOp>) {
    if before == after {
        return;
    }
    match (before, after) {
        (Value::Object(a), Value::Object(b)) => {
            for (key, value) in a {
                let child = format!("{path}/{}", pointer_segment(key));
                match b.get(key) {
                    Some(other) => diff_at(child, value, other, ops),
                    None => ops.push(JsonPatchOp {
                        op: "remove",
                        path: child,
                        value: None,
                    }),
                }
            }
            for (key, value) in b {
                if !a.contains_key(key) {
                    ops.push(JsonPatchOp {
                        op: "add",
                        path: format!("{path}/{}", pointer_segment(key)),
                        value: Some(value.clone()),
                    });
                }
            }
        }
        (Value::Array(a), Value::Array(b)) => {
            let common = a.len().min(b.len());
            for index in 0..common {
                diff_at(format!("{path}/{index}"), &a[index], &b[index], ops);
            }
            // Remove from the end so earlier indexes stay valid.
            for index in (common..a.len()).rev() {
                ops.push(JsonPatchOp {
                    op: "remove",
                    path: format!("{path}/{index}"),
                    value: None,
                });
            }
            for value in &b[common..] {
                ops.push(JsonPatchOp {
                    op: "add",
                    path: format!("{path}/-"),
                    value: Some(value.clone()),
                });
            }
        }
        _ => ops.push(JsonPatchOp {
            op: "replace",
            path,
            value: Some(after.clone()),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn diff_names_each_change_with_an_escaped_pointer() {
        let before = json!({ "title": "A", "a/b": 1, "list": [1, 2, 3], "gone": true });
        let after = json!({ "title": "B", "a/b": 2, "list": [1, 5], "new": { "x": 1 } });
        let ops = json_diff(&before, &after);
        let rendered: Vec<String> = ops
            .iter()
            .map(|op| format!("{} {}", op.op, op.path))
            .collect();
        assert!(rendered.contains(&"replace /title".to_owned()));
        assert!(rendered.contains(&"replace /a~1b".to_owned()));
        assert!(rendered.contains(&"replace /list/1".to_owned()));
        assert!(rendered.contains(&"remove /list/2".to_owned()));
        assert!(rendered.contains(&"remove /gone".to_owned()));
        assert!(rendered.contains(&"add /new".to_owned()));
        assert!(json_diff(&before, &before).is_empty());
    }
}

/// An object's newest published version (V2-D487: what a session started
/// from an agent object reads). `NotFound` when it has none.
pub async fn read_published(pool: &DbPool, object_id: Uuid) -> Result<ObjectVersion, AppError> {
    let row: Option<ObjectVersion> = sqlx::query_as(
        "SELECT o.id AS object_id, o.kind, o.name, v.version_no, v.kind_schema_version, v.state, \
                v.doc, v.content_hash, v.created_at \
         FROM metadata_object o \
         JOIN metadata_object_version v ON v.object_id = o.id \
         WHERE o.id = $1 AND o.is_active AND v.state = 'published' \
         ORDER BY v.version_no DESC \
         LIMIT 1",
    )
    .bind(object_id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::internal)?;
    row.ok_or(AppError::NotFound)
}

/// One object's newest version, as a file export writes it (Y1-T10).
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct ExportRow {
    pub kind: String,
    pub app: String,
    pub name: String,
    pub kind_schema_version: i32,
    pub doc: Value,
}

/// The newest version (the draft, when there is one) of every active object
/// of `kinds`, ordered by kind, app and name. Bounded by each kind's object
/// limit.
pub async fn export_newest(pool: &DbPool, kinds: &[String]) -> Result<Vec<ExportRow>, AppError> {
    let mut rows: Vec<ExportRow> = sqlx::query_as(
        "SELECT DISTINCT ON (o.id) o.kind, o.app, o.name, v.kind_schema_version, v.doc \
         FROM metadata_object o \
         JOIN metadata_object_version v ON v.object_id = o.id \
         WHERE o.is_active AND o.kind = ANY($1) \
         ORDER BY o.id, v.version_no DESC",
    )
    .bind(kinds)
    .fetch_all(pool)
    .await
    .map_err(AppError::internal)?;
    rows.sort_by(|a, b| (&a.kind, &a.app, &a.name).cmp(&(&b.kind, &b.app, &b.name)));
    Ok(rows)
}

/// The id of the active object of `kind` named `name` in `app`, if any.
pub async fn find_by_name(
    tx: &mut Tx<'_>,
    kind: &str,
    app: &str,
    name: &str,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT id FROM metadata_object WHERE kind = $1 AND app = $2 AND name = $3 AND is_active",
    )
    .bind(kind)
    .bind(app)
    .bind(name)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)
}

/// An object found by name, with its newest published version, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedState {
    pub id: Uuid,
    /// The newest published version's number and content hash.
    pub published: Option<(i64, String)>,
}

/// The object of `kind` named `name` in `app` and its newest published
/// version, or `None` when no such object exists. For a blueprint plan
/// (N12-T3).
pub async fn published_state(
    pool: &DbPool,
    kind: &str,
    app: &str,
    name: &str,
) -> Result<Option<PublishedState>, AppError> {
    let row: Option<(Uuid, Option<i64>, Option<String>)> = sqlx::query_as(
        "SELECT o.id, v.version_no, v.content_hash          FROM metadata_object o          LEFT JOIN LATERAL (              SELECT version_no, content_hash FROM metadata_object_version              WHERE object_id = o.id AND state = 'published'              ORDER BY version_no DESC LIMIT 1          ) v ON true          WHERE o.kind = $1 AND o.app = $2 AND o.name = $3 AND o.is_active",
    )
    .bind(kind)
    .bind(app)
    .bind(name)
    .fetch_optional(pool)
    .await
    .map_err(AppError::internal)?;
    Ok(row.map(|(id, version, hash)| PublishedState {
        id,
        published: version.zip(hash),
    }))
}
