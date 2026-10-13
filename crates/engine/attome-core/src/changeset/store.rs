//! Changeset store functions over `changeset` and
//! `changeset_operation` (migration `0521_changeset_store.sql`):
//! open, read, lock, the one-time `args` fill, close, abandon, and sealing an
//! automatic changeset.
//!
//! Close's translation of snapshots into logical `args`, the v1 document and
//! its checksum live in `attome-server` (they need the bundle model); these
//! functions only move the row through its lifecycle under a row lock and
//! enforce the rules that do not need translation: close refuses an empty
//! changeset, abandon refuses a non-empty one, and neither touches a changeset
//! that is not open.

use attome_db::{DbPool, Tx};
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgExecutor;
use uuid::Uuid;

use super::errors;
use super::model::{ChangesetStatus, Layer, Origin};

/// Every column a caller reads, enumerated (guidelines §4: no `SELECT *`).
const CHANGESET_COLUMNS: &str = "id, layer, scope, name, title, description, origin, status, \
     requires, op_count, opened_log_id, author_ref, author_label, opened_at, closed_at, \
     document, checksum, ops_hash, created_at, updated_at, row_version";

/// A changeset row.
#[derive(Debug, Clone)]
pub struct ChangesetRow {
    pub id: Uuid,
    pub layer: Layer,
    pub scope: String,
    pub name: String,
    pub title: String,
    pub description: String,
    pub origin: Origin,
    pub status: ChangesetStatus,
    pub requires: Value,
    pub op_count: i32,
    pub opened_log_id: i64,
    pub author_ref: Option<Uuid>,
    pub author_label: String,
    pub opened_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
    pub document: Option<Value>,
    pub checksum: Option<String>,
    pub ops_hash: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub row_version: i64,
}

#[derive(sqlx::FromRow)]
struct RawChangeset {
    id: Uuid,
    layer: String,
    scope: String,
    name: String,
    title: String,
    description: String,
    origin: String,
    status: String,
    requires: Value,
    op_count: i32,
    opened_log_id: i64,
    author_ref: Option<Uuid>,
    author_label: String,
    opened_at: DateTime<Utc>,
    closed_at: Option<DateTime<Utc>>,
    document: Option<Value>,
    checksum: Option<String>,
    ops_hash: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    row_version: i64,
}

impl TryFrom<RawChangeset> for ChangesetRow {
    type Error = AppError;

    fn try_from(r: RawChangeset) -> Result<Self, AppError> {
        // The table's CHECK constraints make these unreachable; a failure means
        // the schema and this code disagree, which is an internal error.
        let layer = Layer::parse(&r.layer)
            .ok_or_else(|| AppError::internal(format!("unknown changeset layer {:?}", r.layer)))?;
        let origin = Origin::parse(&r.origin).ok_or_else(|| {
            AppError::internal(format!("unknown changeset origin {:?}", r.origin))
        })?;
        let status = ChangesetStatus::parse(&r.status).ok_or_else(|| {
            AppError::internal(format!("unknown changeset status {:?}", r.status))
        })?;
        Ok(Self {
            id: r.id,
            layer,
            scope: r.scope,
            name: r.name,
            title: r.title,
            description: r.description,
            origin,
            status,
            requires: r.requires,
            op_count: r.op_count,
            opened_log_id: r.opened_log_id,
            author_ref: r.author_ref,
            author_label: r.author_label,
            opened_at: r.opened_at,
            closed_at: r.closed_at,
            document: r.document,
            checksum: r.checksum,
            ops_hash: r.ops_hash,
            created_at: r.created_at,
            updated_at: r.updated_at,
            row_version: r.row_version,
        })
    }
}

/// One recorded operation.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OperationRow {
    pub id: Uuid,
    pub changeset_ref: Uuid,
    pub seq: i32,
    pub op: String,
    pub phase: String,
    pub object_kind: String,
    pub object_ref: Option<Uuid>,
    pub target: Value,
    pub snapshot: Value,
    pub args: Option<Value>,
    pub changed: Vec<String>,
    pub route: String,
    pub request_id: Option<String>,
    pub actor_ref: Option<Uuid>,
    pub recorded_at: DateTime<Utc>,
}

/// What `open` needs. `layer` may be platform, product or project; the
/// customer layer is Phase 3.
#[derive(Debug, Clone)]
pub struct NewChangeset {
    pub layer: Layer,
    pub scope: String,
    pub name: String,
    pub title: String,
    pub description: String,
    pub requires: Value,
    pub author_ref: Option<Uuid>,
    pub author_label: String,
}

/// What close writes, computed by the caller (attome-server) from the
/// translated operations.
#[derive(Debug, Clone)]
pub struct Seal {
    pub document: Value,
    /// `sha256:` + 64 lowercase hex.
    pub checksum: String,
    pub ops_hash: String,
}

/// `^[a-z0-9]+([-_][a-z0-9]+)*$` — the table's scope CHECK.
pub fn is_valid_scope(scope: &str) -> bool {
    is_dashed(scope, &['-', '_'])
}

/// `^[a-z0-9]+(-[a-z0-9]+)*$`, at most 60 characters — the table's name CHECK.
pub fn is_valid_name(name: &str) -> bool {
    name.len() <= 60 && is_dashed(name, &['-'])
}

fn is_dashed(value: &str, separators: &[char]) -> bool {
    !value.is_empty()
        && value.split(|c| separators.contains(&c)).all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        })
}

fn is_valid_checksum(checksum: &str) -> bool {
    checksum.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    })
}

/// Checks `new`'s client-supplied fields, naming every failure at once.
pub fn validate_new(new: &NewChangeset) -> Result<(), AppError> {
    let mut problems = Vec::new();
    if new.layer == Layer::Customer {
        problems.push("layer: customer changesets are not authored in this release (Phase 3)");
    }
    if !is_valid_scope(&new.scope) {
        problems.push("scope: lowercase letters and digits, joined by '-' or '_'");
    }
    if !is_valid_name(&new.name) {
        problems.push("name: lowercase letters and digits joined by '-', at most 60 characters");
    }
    let title_len = new.title.chars().count();
    if title_len == 0 || title_len > 200 || new.title.trim().is_empty() {
        problems.push("title: 1 to 200 characters");
    }
    if !new.requires.is_object() {
        problems.push("requires: must be an object");
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(AppError::Validation(problems.join("; ")))
    }
}

/// The metadata change-log watermark a changeset records at open (close
/// warns about entity changes after it that no operation covers).
pub(crate) const LOG_WATERMARK_SQL: &str = "(SELECT COALESCE(MAX(id), 0) FROM metadata_change_log)";

/// Opens an authored changeset. One open changeset per (layer, scope, name):
/// a second is `409 changeset_name_taken`.
pub async fn open(db: &DbPool, new: &NewChangeset) -> Result<ChangesetRow, AppError> {
    validate_new(new)?;
    let sql = format!(
        "INSERT INTO changeset \
             (layer, scope, name, title, description, origin, status, requires, \
              opened_log_id, author_ref, author_label) \
         VALUES ($1, $2, $3, $4, $5, 'authored', 'open', $6, {LOG_WATERMARK_SQL}, $7, $8) \
         RETURNING {CHANGESET_COLUMNS}"
    );
    let raw: RawChangeset = sqlx::query_as(&sql)
        .bind(new.layer.as_str())
        .bind(&new.scope)
        .bind(&new.name)
        .bind(&new.title)
        .bind(&new.description)
        .bind(&new.requires)
        .bind(new.author_ref)
        .bind(&new.author_label)
        .fetch_one(db)
        .await
        .map_err(|e| {
            if e.as_database_error()
                .and_then(|d| d.code())
                .is_some_and(|code| code == "23505")
            {
                AppError::Conflict(errors::CHANGESET_NAME_TAKEN)
            } else {
                AppError::internal(e)
            }
        })?;
    raw.try_into()
}

/// One changeset, or `None`.
pub async fn get<'e>(db: impl PgExecutor<'e>, id: Uuid) -> Result<Option<ChangesetRow>, AppError> {
    let sql = format!("SELECT {CHANGESET_COLUMNS} FROM changeset WHERE id = $1");
    let raw: Option<RawChangeset> = sqlx::query_as(&sql)
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
    raw.map(TryInto::try_into).transpose()
}

/// The changeset row, locked `FOR UPDATE` in `tx`, or `None`.
pub async fn lock(tx: &mut Tx<'_>, id: Uuid) -> Result<Option<ChangesetRow>, AppError> {
    let sql = format!("SELECT {CHANGESET_COLUMNS} FROM changeset WHERE id = $1 FOR UPDATE");
    let raw: Option<RawChangeset> = sqlx::query_as(&sql)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    raw.map(TryInto::try_into).transpose()
}

/// A changeset's operations, in `seq` order.
pub async fn operations<'e>(
    db: impl PgExecutor<'e>,
    changeset_id: Uuid,
) -> Result<Vec<OperationRow>, AppError> {
    sqlx::query_as(
        "SELECT id, changeset_ref, seq, op, phase, object_kind, object_ref, target, snapshot, \
                args, changed, route, request_id, actor_ref, recorded_at \
         FROM changeset_operation WHERE changeset_ref = $1 ORDER BY seq",
    )
    .bind(changeset_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// The one-time `args` fill at close. Refuses (internal error) when the
/// operation does not exist or already has its args: operations are
/// append-only apart from this single write.
pub async fn fill_args(
    tx: &mut Tx<'_>,
    changeset_id: Uuid,
    seq: i32,
    args: &Value,
) -> Result<(), AppError> {
    let done = sqlx::query(
        "UPDATE changeset_operation SET args = $3 \
         WHERE changeset_ref = $1 AND seq = $2 AND args IS NULL",
    )
    .bind(changeset_id)
    .bind(seq)
    .bind(args)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if done.rows_affected() != 1 {
        return Err(AppError::internal(format!(
            "changeset {changeset_id} operation {seq}: missing, or its args are already set"
        )));
    }
    Ok(())
}

/// Locks an open changeset for a lifecycle change and checks the caller's
/// `If-Match` version when one was sent.
async fn lock_open(
    tx: &mut Tx<'_>,
    id: Uuid,
    expected_row_version: Option<i64>,
) -> Result<ChangesetRow, AppError> {
    let row = lock(tx, id).await?.ok_or(AppError::NotFound)?;
    if row.status != ChangesetStatus::Open {
        return Err(AppError::Conflict(errors::CHANGESET_NOT_OPEN));
    }
    if expected_row_version.is_some_and(|v| v != row.row_version) {
        return Err(AppError::VersionConflict);
    }
    Ok(row)
}

/// Closes an authored changeset with its sealed document. Refuses an empty
/// changeset (`409 changeset_empty`), one that is not open
/// (`409 changeset_not_open`) and a stale `If-Match` (`409 version_conflict`).
pub async fn close(
    tx: &mut Tx<'_>,
    id: Uuid,
    expected_row_version: Option<i64>,
    seal: &Seal,
) -> Result<ChangesetRow, AppError> {
    let row = lock_open(tx, id, expected_row_version).await?;
    if row.op_count == 0 {
        return Err(AppError::Conflict(errors::CHANGESET_EMPTY));
    }
    if !is_valid_checksum(&seal.checksum) {
        return Err(AppError::internal(
            "close: the seal's checksum is malformed",
        ));
    }
    let sql = format!(
        "UPDATE changeset \
         SET status = 'closed', closed_at = now(), document = $2, checksum = $3, ops_hash = $4, \
             updated_at = now(), row_version = row_version + 1 \
         WHERE id = $1 AND status = 'open' \
         RETURNING {CHANGESET_COLUMNS}"
    );
    let raw: RawChangeset = sqlx::query_as(&sql)
        .bind(id)
        .bind(&seal.document)
        .bind(&seal.checksum)
        .bind(&seal.ops_hash)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    raw.try_into()
}

/// Abandons an open changeset. Allowed only while it holds no operation
/// (`409 changeset_not_empty` otherwise): abandoning recorded work would leave
/// the development database with changes nothing records (design §4.6).
pub async fn abandon(
    tx: &mut Tx<'_>,
    id: Uuid,
    expected_row_version: Option<i64>,
) -> Result<ChangesetRow, AppError> {
    let row = lock_open(tx, id, expected_row_version).await?;
    if row.op_count != 0 {
        return Err(AppError::Conflict(errors::CHANGESET_NOT_EMPTY));
    }
    let sql = format!(
        "UPDATE changeset \
         SET status = 'abandoned', updated_at = now(), row_version = row_version + 1 \
         WHERE id = $1 AND status = 'open' AND op_count = 0 \
         RETURNING {CHANGESET_COLUMNS}"
    );
    let raw: RawChangeset = sqlx::query_as(&sql)
        .bind(id)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    raw.try_into()
}

/// Seals a closed automatic changeset (design §4.6: the same translation
/// without the lock-and-refuse steps). Returns `false` when there was nothing
/// to seal: not automatic, not closed, or already sealed.
pub async fn seal_automatic(tx: &mut Tx<'_>, id: Uuid, seal: &Seal) -> Result<bool, AppError> {
    if !is_valid_checksum(&seal.checksum) {
        return Err(AppError::internal("seal: the checksum is malformed"));
    }
    let done = sqlx::query(
        "UPDATE changeset \
         SET document = $2, checksum = $3, ops_hash = $4, \
             updated_at = now(), row_version = row_version + 1 \
         WHERE id = $1 AND status = 'closed' AND origin IN ('auto', 'break_glass') \
           AND document IS NULL",
    )
    .bind(id)
    .bind(&seal.document)
    .bind(&seal.checksum)
    .bind(&seal.ops_hash)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(done.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn new(layer: Layer, scope: &str, name: &str, title: &str) -> NewChangeset {
        NewChangeset {
            layer,
            scope: scope.into(),
            name: name.into(),
            title: title.into(),
            description: String::new(),
            requires: json!({}),
            author_ref: None,
            author_label: "test".into(),
        }
    }

    #[test]
    fn scope_and_name_follow_the_table_checks() {
        for ok in ["acme", "acme_co", "acme-co", "a1"] {
            assert!(is_valid_scope(ok), "{ok}");
        }
        for bad in ["", "Acme", "acme-", "_acme", "acme__co", "acme co"] {
            assert!(!is_valid_scope(bad), "{bad}");
        }
        for ok in ["accounts", "add-accounts-2"] {
            assert!(is_valid_name(ok), "{ok}");
        }
        for bad in ["", "add_accounts", "-a", "a--b", &"a".repeat(61)] {
            assert!(!is_valid_name(bad), "{bad}");
        }
    }

    #[test]
    fn a_new_changeset_is_validated_in_one_pass() {
        assert!(validate_new(&new(Layer::Project, "acme", "accounts", "Accounts")).is_ok());
        let Err(AppError::Validation(message)) =
            validate_new(&new(Layer::Customer, "Acme", "a_b", ""))
        else {
            panic!("expected a validation error");
        };
        for part in ["layer", "scope", "name", "title"] {
            assert!(message.contains(part), "{message} names {part}");
        }
        let mut bad_requires = new(Layer::Platform, "core", "x", "X");
        bad_requires.requires = json!([]);
        assert!(validate_new(&bad_requires).is_err());
    }

    #[test]
    fn checksums_are_sha256_lowercase_hex() {
        assert!(is_valid_checksum(&format!("sha256:{}", "a".repeat(64))));
        assert!(!is_valid_checksum(&format!("sha256:{}", "A".repeat(64))));
        assert!(!is_valid_checksum(&"a".repeat(64)));
        assert!(!is_valid_checksum("sha256:abc"));
    }
}
