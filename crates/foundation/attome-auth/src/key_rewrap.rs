//! Q18-T4: the rewrap job for every registered encrypted column.
//!
//! After a key rotation (a new active key added to a ring, the old one kept
//! until this finishes), [`rewrap_columns`] walks each column of
//! [`crate::encrypted_columns::ENCRYPTED_COLUMNS`] whose domain has a ring,
//! 500 rows at a time in key order, and reseals every value not already
//! under the ring's active key, against the same associated data and in the
//! same envelope version ([`crate::envelope::reseal_bytes`]). Each write is
//! a compare-and-set on the old value, so a row changed meanwhile keeps its
//! new value; a value that does not open is counted and logged, never
//! overwritten.
//!
//! Progress is kept per column in `key_rewrap_progress` after every batch,
//! so a run stopped part-way (a restart, a deploy) resumes after the last
//! key it finished; a finished column starts again from the top on the next
//! run.

use attome_config::KeyRing;
use attome_db::DbPool;
use attome_types::AppError;
use base64::{Engine, engine::general_purpose::STANDARD as B64};

use crate::encrypted_columns::{ENCRYPTED_COLUMNS, EncryptedColumn, Sealing};
use crate::envelope::{RowBinding, reseal_bytes, stored_key_id_bytes};

/// Rows per batch.
pub const BATCH_SIZE: i64 = 500;

/// Totals for one column in one run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ColumnTotals {
    pub scanned: u64,
    pub rewrapped: u64,
    pub failed: u64,
}

/// What one run did, per column; `skipped` names the columns whose domain
/// has no ring configured.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RewrapReport {
    pub columns: Vec<(EncryptedColumn, ColumnTotals)>,
    pub skipped: Vec<EncryptedColumn>,
}

impl RewrapReport {
    pub fn totals(&self) -> ColumnTotals {
        self.columns
            .iter()
            .fold(ColumnTotals::default(), |acc, (_, t)| ColumnTotals {
                scanned: acc.scanned + t.scanned,
                rewrapped: acc.rewrapped + t.rewrapped,
                failed: acc.failed + t.failed,
            })
    }
}

/// One stored value, as the column holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stored {
    Text(String),
    Bytes(Vec<u8>),
}

/// The associated data a row's value is sealed against. `pair` holds the
/// two columns [`Sealing::BytesPair`] names; `bound` whether a text value
/// is a `0x02` (row-bound) envelope.
fn row_aad(
    col: &EncryptedColumn,
    key: &str,
    pair: Option<(&str, &str)>,
    bound: bool,
) -> Result<Vec<u8>, AppError> {
    let bound_to = |table: &str, column: &str| -> Result<Vec<u8>, AppError> {
        Ok(RowBinding {
            table,
            column,
            row_id: key.parse().map_err(|_| {
                AppError::internal(format!(
                    "{}.{}: a bound value's row key is not a UUID",
                    col.table, col.column
                ))
            })?,
        }
        .aad())
    };
    Ok(match col.sealing {
        Sealing::Text if bound => bound_to(col.table, col.column)?,
        Sealing::TextBoundAs { table, column } if bound => bound_to(table, column)?,
        Sealing::Text | Sealing::TextBoundAs { .. } => Vec::new(),
        Sealing::BytesKeyAad => key
            .parse::<uuid::Uuid>()
            .map_err(|_| {
                AppError::internal(format!(
                    "{}.{}: the row key is not a UUID",
                    col.table, col.column
                ))
            })?
            .as_bytes()
            .to_vec(),
        Sealing::BytesPrefixedKey(prefix) => format!("{prefix}{key}").into_bytes(),
        Sealing::BytesPair { prefix, .. } => {
            let (first, second) = pair.ok_or_else(|| {
                AppError::internal(format!(
                    "{}.{}: the row's pair is missing",
                    col.table, col.column
                ))
            })?;
            format!("{prefix}{first}:{second}").into_bytes()
        }
    })
}

/// The value resealed under `ring`'s active key, or `None` when it already
/// is. Pure: the job's per-row step.
pub fn reseal_row(
    col: &EncryptedColumn,
    ring: &KeyRing,
    key: &str,
    pair: Option<(&str, &str)>,
    stored: &Stored,
) -> Result<Option<Stored>, AppError> {
    let field = format!("{}.{}", col.table, col.column);
    let combined = match stored {
        Stored::Text(text) => B64
            .decode(text)
            .map_err(|_| AppError::internal(format!("{field} is not valid base64")))?,
        Stored::Bytes(bytes) => bytes.clone(),
    };
    if stored_key_id_bytes(&combined).as_deref() == Some(ring.active_key_id.as_str()) {
        return Ok(None);
    }
    let bound = combined.first() == Some(&0x02);
    let aad = row_aad(col, key, pair, bound)?;
    let fresh = reseal_bytes(&field, ring, &combined, &aad)?;
    Ok(Some(match stored {
        Stored::Text(_) => Stored::Text(B64.encode(fresh)),
        Stored::Bytes(_) => Stored::Bytes(fresh),
    }))
}

/// A registry identifier, quoted. The registry is static and reviewed; this
/// refuses anything but lowercase identifier characters all the same.
fn ident(name: &str) -> Result<String, AppError> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(AppError::internal(format!(
            "encrypted column registry: {name:?} is not an identifier"
        )));
    }
    Ok(quote_ident(name))
}

/// `name` in double quotes, each embedded quote doubled. Call it on a name
/// [`ident`] accepted.
fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// One row of a batch: its key, its pair (for [`Sealing::BytesPair`]) and
/// its value.
type Row = (String, Option<(String, String)>, Stored);

async fn fetch_batch(
    db: &DbPool,
    col: &EncryptedColumn,
    after: &str,
    batch: i64,
) -> Result<Vec<Row>, AppError> {
    for name in [col.table, col.column, col.key] {
        ident(name)?;
    }
    let sql = match col.sealing {
        Sealing::BytesPair { first, second, .. } => {
            ident(first)?;
            ident(second)?;
            format!(
                "SELECT {key}::text, {column}, {first}::text, {second}::text FROM {table} \
                 WHERE {column} IS NOT NULL AND {key}::text > $1 \
                 ORDER BY {key}::text LIMIT $2",
                key = quote_ident(col.key),
                column = quote_ident(col.column),
                first = quote_ident(first),
                second = quote_ident(second),
                table = quote_ident(col.table),
            )
        }
        _ => format!(
            "SELECT {key}::text, {column}, NULL::text, NULL::text FROM {table} \
             WHERE {column} IS NOT NULL AND {key}::text > $1 \
             ORDER BY {key}::text LIMIT $2",
            key = quote_ident(col.key),
            column = quote_ident(col.column),
            table = quote_ident(col.table),
        ),
    };
    let sql = attome_db::tag_dynamic("key_rewrap.batch", &sql);
    let rows = match col.sealing {
        Sealing::Text | Sealing::TextBoundAs { .. } => {
            sqlx::query_as::<_, (String, String, Option<String>, Option<String>)>(&sql)
                .bind(after)
                .bind(batch)
                .fetch_all(db)
                .await
                .map_err(AppError::internal)?
                .into_iter()
                .map(|(k, v, a, b)| (k, a.zip(b), Stored::Text(v)))
                .collect()
        }
        _ => sqlx::query_as::<_, (String, Vec<u8>, Option<String>, Option<String>)>(&sql)
            .bind(after)
            .bind(batch)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?
            .into_iter()
            .map(|(k, v, a, b)| (k, a.zip(b), Stored::Bytes(v)))
            .collect(),
    };
    Ok(rows)
}

/// Writes `fresh` over `old` for row `key`; `false` when the row changed
/// meanwhile.
async fn write_row(
    db: &DbPool,
    col: &EncryptedColumn,
    key: &str,
    old: &Stored,
    fresh: &Stored,
) -> Result<bool, AppError> {
    for name in [col.table, col.column, col.key] {
        ident(name)?;
    }
    let sql = format!(
        "UPDATE {table} SET {column} = $1 WHERE {key}::text = $2 AND {column} = $3",
        table = quote_ident(col.table),
        column = quote_ident(col.column),
        key = quote_ident(col.key),
    );
    let sql = attome_db::tag_dynamic("key_rewrap.write", &sql);
    let query = sqlx::query(&sql);
    let query = match (fresh, old) {
        (Stored::Text(new), Stored::Text(was)) => query.bind(new).bind(key).bind(was),
        (Stored::Bytes(new), Stored::Bytes(was)) => query.bind(new).bind(key).bind(was),
        _ => return Err(AppError::internal("key rewrap: a value changed shape")),
    };
    Ok(query
        .execute(db)
        .await
        .map_err(AppError::internal)?
        .rows_affected()
        > 0)
}

/// One batch of `col` after `after`: the totals and the last key read.
pub async fn rewrap_batch(
    db: &DbPool,
    col: &EncryptedColumn,
    ring: &KeyRing,
    after: &str,
    batch: i64,
) -> Result<(ColumnTotals, Option<String>), AppError> {
    let rows = fetch_batch(db, col, after, batch).await?;
    let mut totals = ColumnTotals {
        scanned: rows.len() as u64,
        ..ColumnTotals::default()
    };
    let last = rows.last().map(|(k, _, _)| k.clone());
    for (key, pair, stored) in rows {
        let pair = pair.as_ref().map(|(a, b)| (a.as_str(), b.as_str()));
        match reseal_row(col, ring, &key, pair, &stored) {
            Ok(None) => {}
            Ok(Some(fresh)) => {
                if write_row(db, col, &key, &stored, &fresh).await? {
                    totals.rewrapped += 1;
                }
            }
            Err(error) => {
                // Never overwritten: the value stays for an operator to look at.
                tracing::error!(
                    table = col.table,
                    column = col.column,
                    row = %key,
                    %error,
                    "key rewrap: a value does not open with its ring"
                );
                totals.failed += 1;
            }
        }
    }
    Ok((totals, last))
}

/// Where `col`'s last unfinished run stopped, or `""` to start at the top
/// (and the progress row reset for a new run).
async fn resume_point(db: &DbPool, col: &EncryptedColumn) -> Result<String, AppError> {
    let row: Option<(Option<String>, bool)> = sqlx::query_as(
        "SELECT last_key, finished_at IS NOT NULL FROM key_rewrap_progress \
         WHERE table_name = $1 AND column_name = $2",
    )
    .bind(col.table)
    .bind(col.column)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    if let Some((last_key, false)) = row {
        return Ok(last_key.unwrap_or_default());
    }
    sqlx::query(
        "INSERT INTO key_rewrap_progress \
             (table_name, column_name, domain, last_key, scanned, rewrapped, failed, started_at, finished_at) \
         VALUES ($1, $2, $3, NULL, 0, 0, 0, NOW(), NULL) \
         ON CONFLICT (table_name, column_name) DO UPDATE SET \
             domain = EXCLUDED.domain, last_key = NULL, scanned = 0, rewrapped = 0, failed = 0, \
             started_at = NOW(), finished_at = NULL",
    )
    .bind(col.table)
    .bind(col.column)
    .bind(col.domain)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(String::new())
}

async fn record_batch(
    db: &DbPool,
    col: &EncryptedColumn,
    totals: &ColumnTotals,
    last: Option<&str>,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE key_rewrap_progress SET \
             last_key = COALESCE($3, last_key), scanned = scanned + $4, \
             rewrapped = rewrapped + $5, failed = failed + $6, \
             finished_at = CASE WHEN $4 = 0 THEN NOW() END \
         WHERE table_name = $1 AND column_name = $2",
    )
    .bind(col.table)
    .bind(col.column)
    .bind(last)
    .bind(totals.scanned as i64)
    .bind(totals.rewrapped as i64)
    .bind(totals.failed as i64)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Rewraps every column of `columns` whose domain `ring_for` gives a ring,
/// to the end, resuming where an unfinished run stopped.
pub async fn rewrap_columns(
    db: &DbPool,
    columns: &[EncryptedColumn],
    ring_for: impl Fn(&str) -> Option<KeyRing>,
    batch: i64,
) -> Result<RewrapReport, AppError> {
    let mut report = RewrapReport::default();
    for col in columns {
        let Some(ring) = ring_for(col.domain).filter(|r| !r.is_empty()) else {
            report.skipped.push(*col);
            continue;
        };
        let mut after = resume_point(db, col).await?;
        let mut totals = ColumnTotals::default();
        loop {
            let (batch_totals, last) = rewrap_batch(db, col, &ring, &after, batch).await?;
            record_batch(db, col, &batch_totals, last.as_deref()).await?;
            totals.scanned += batch_totals.scanned;
            totals.rewrapped += batch_totals.rewrapped;
            totals.failed += batch_totals.failed;
            match last {
                Some(last) if batch_totals.scanned > 0 => after = last,
                _ => break,
            }
        }
        tracing::info!(
            table = col.table,
            column = col.column,
            domain = col.domain,
            scanned = totals.scanned,
            rewrapped = totals.rewrapped,
            failed = totals.failed,
            "key rewrap: column done"
        );
        report.columns.push((*col, totals));
    }
    Ok(report)
}

/// [`rewrap_columns`] over the whole registry.
pub async fn rewrap_registry(
    db: &DbPool,
    ring_for: impl Fn(&str) -> Option<KeyRing>,
) -> Result<RewrapReport, AppError> {
    rewrap_columns(db, ENCRYPTED_COLUMNS, ring_for, BATCH_SIZE).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{encrypt, encrypt_bound, encrypt_bytes_with_aad, stored_key_id};
    use std::collections::HashMap;
    use uuid::Uuid;

    fn ring(keys: &[(&str, &str)], active: &str) -> KeyRing {
        KeyRing {
            keys: keys
                .iter()
                .map(|(id, hex)| ((*id).to_owned(), (*hex).to_owned()))
                .collect::<HashMap<_, _>>(),
            active_key_id: active.to_owned(),
        }
    }

    fn column(table: &'static str, sealing: Sealing) -> EncryptedColumn {
        EncryptedColumn {
            table,
            column: "secret",
            domain: "test",
            key: "id",
            sealing,
        }
    }

    const OLD: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const NEW: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const OTHER_OLD: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    const OTHER_NEW: &str = "4444444444444444444444444444444444444444444444444444444444444444";

    /// Two domains, each rotated from an old key to a new one: every shape
    /// is resealed under its own ring's new key, opens again against the
    /// same associated data, and keeps its envelope version.
    #[test]
    fn rewrap_all_reseals_two_domains_after_a_rotation() {
        let first_before = ring(&[("k1", OLD)], "k1");
        let first_after = ring(&[("k1", OLD), ("k2", NEW)], "k2");
        let second_before = ring(&[("a", OTHER_OLD)], "a");
        let second_after = ring(&[("a", OTHER_OLD), ("b", OTHER_NEW)], "b");
        let id = Uuid::now_v7();

        // Domain one: an unbound and a bound text value.
        let plain = column("plain_t", Sealing::Text);
        let stored = Stored::Text(encrypt("f", &first_before, "s3cret").unwrap());
        let Some(Stored::Text(fresh)) =
            reseal_row(&plain, &first_after, &id.to_string(), None, &stored).unwrap()
        else {
            panic!("resealed")
        };
        assert_eq!(stored_key_id(&fresh).as_deref(), Some("k2"));
        assert_eq!(
            crate::envelope::decrypt("f", &first_after, &fresh)
                .unwrap()
                .into_exposed(),
            "s3cret"
        );
        assert!(
            !crate::envelope::stored_is_bound(&fresh),
            "unbound stays unbound"
        );

        let bound_col = column("bound_t", Sealing::Text);
        let binding = RowBinding {
            table: "bound_t",
            column: "secret",
            row_id: id,
        };
        let stored = Stored::Text(encrypt_bound("f", &first_before, "tok", binding).unwrap());
        let Some(Stored::Text(fresh)) =
            reseal_row(&bound_col, &first_after, &id.to_string(), None, &stored).unwrap()
        else {
            panic!("resealed")
        };
        assert!(
            crate::envelope::stored_is_bound(&fresh),
            "bound stays bound"
        );
        assert_eq!(
            crate::envelope::decrypt_bound("f", &first_after, &fresh, binding)
                .unwrap()
                .into_exposed(),
            "tok"
        );

        // A text value sealed through another column's helper keeps that
        // column's binding.
        let borrowed = column(
            "borrowed_t",
            Sealing::TextBoundAs {
                table: "bound_t",
                column: "secret",
            },
        );
        let stored = Stored::Text(encrypt_bound("f", &first_before, "hook", binding).unwrap());
        let Some(Stored::Text(fresh)) =
            reseal_row(&borrowed, &first_after, &id.to_string(), None, &stored).unwrap()
        else {
            panic!("resealed")
        };
        assert_eq!(
            crate::envelope::decrypt_bound("f", &first_after, &fresh, binding)
                .unwrap()
                .into_exposed(),
            "hook"
        );

        // Domain two: the three bytea shapes.
        for (sealing, aad) in [
            (Sealing::BytesKeyAad, id.as_bytes().to_vec()),
            (
                Sealing::BytesPrefixedKey("report/v1:"),
                format!("report/v1:{id}").into_bytes(),
            ),
            (
                Sealing::BytesPair {
                    prefix: "archive/v2:",
                    first: "a",
                    second: "b",
                },
                b"archive/v2:x:y".to_vec(),
            ),
        ] {
            let col = column("bytes_t", sealing);
            let stored =
                Stored::Bytes(encrypt_bytes_with_aad("f", &second_before, b"value", &aad).unwrap());
            let Some(Stored::Bytes(fresh)) = reseal_row(
                &col,
                &second_after,
                &id.to_string(),
                Some(("x", "y")),
                &stored,
            )
            .unwrap() else {
                panic!("resealed")
            };
            assert_eq!(stored_key_id_bytes(&fresh).as_deref(), Some("b"));
            assert_eq!(
                crate::envelope::decrypt_bytes_with_aad("f", &second_after, &fresh, &aad).unwrap(),
                b"value"
            );
            // Already under the active key: nothing to do.
            assert_eq!(
                reseal_row(
                    &col,
                    &second_after,
                    &id.to_string(),
                    Some(("x", "y")),
                    &Stored::Bytes(fresh)
                )
                .unwrap(),
                None
            );
        }
    }

    /// A value sealed for another row, or under a key the ring no longer
    /// holds, is refused, never resealed into something else.
    #[test]
    fn rewrap_all_refuses_a_value_that_does_not_open() {
        let before = ring(&[("k1", OLD)], "k1");
        let after = ring(&[("k1", OLD), ("k2", NEW)], "k2");
        let col = column("bytes_t", Sealing::BytesKeyAad);
        let sealed_for = Uuid::now_v7();
        let stored = Stored::Bytes(
            encrypt_bytes_with_aad("f", &before, b"v", sealed_for.as_bytes()).unwrap(),
        );
        assert!(reseal_row(&col, &after, &Uuid::now_v7().to_string(), None, &stored).is_err());
        let dropped = ring(&[("k2", NEW)], "k2");
        assert!(reseal_row(&col, &dropped, &sealed_for.to_string(), None, &stored).is_err());
    }

    #[test]
    fn rewrap_all_registry_names_only_identifiers() {
        for col in ENCRYPTED_COLUMNS {
            for name in [col.table, col.column, col.key] {
                assert!(ident(name).is_ok(), "{name}");
            }
        }
        assert!(ident("x; DROP TABLE y").is_err());
    }
}
