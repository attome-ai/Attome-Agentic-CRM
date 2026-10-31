//! AB8-T7: the rules of `attome upgrade rollback` and `attome upgrade contract`,
//! and the statements they run.
//!
//! A release adds structure at apply and removes it only here, once its hold
//! period has passed. After that the old binary no longer finds what it reads,
//! so rollback is refused and only a point-in-time restore goes back.

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::release_manifest::ContractSql;

/// What a contract file waits on or fails with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractError {
    /// The upgrade has not been verified as finished.
    NotFinished,
    /// The file's content is not what the signed manifest names.
    HashMismatch { file: String },
}

impl std::fmt::Display for ContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFinished => f.write_str("the upgrade is not verified as finished"),
            Self::HashMismatch { file } => {
                write!(f, "{file} is not the file the signed manifest names")
            }
        }
    }
}

/// The upgrade row these decisions read.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UpgradeRow {
    pub id: Uuid,
    pub to_version: Option<String>,
    pub status: String,
    pub finished_at: Option<DateTime<Utc>>,
    pub safety_point: Option<String>,
    pub contract_applied_at: Option<DateTime<Utc>>,
    pub check_report: Option<serde_json::Value>,
}

/// Whether the old binary may come back; `Err` says what to do instead. Pure.
pub fn rollback_allowed(upgrade: &UpgradeRow, now: DateTime<Utc>) -> Result<(), String> {
    let Some(applied) = upgrade.contract_applied_at else {
        return Ok(());
    };
    let point = upgrade.safety_point.as_deref().unwrap_or("none recorded");
    let lost = (now - applied).num_minutes();
    Err(format!(
        "contract SQL ran at {applied}, so the old binary would not find what it reads. Only a \
         point-in-time restore to safety point {point} goes back, losing at least {lost} minutes \
         of data"
    ))
}

/// The contract files whose hold period has passed. Pure.
pub fn eligible(
    files: &[ContractSql],
    finished_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Vec<&ContractSql> {
    files
        .iter()
        .filter(|f| finished_at + Duration::days(i64::from(f.eligible_after_days)) <= now)
        .collect()
}

/// Refuses a file whose content is not the one the manifest signed. Pure.
pub fn check_file(file: &ContractSql, bytes: &[u8]) -> Result<(), ContractError> {
    if hex::encode(Sha256::digest(bytes)) == file.sha256 {
        Ok(())
    } else {
        Err(ContractError::HashMismatch {
            file: file.file.clone(),
        })
    }
}

/// The upgrade to `version`, the latest when several ran.
pub async fn upgrade_to(
    db: &attome_db::DbPool,
    version: &str,
) -> Result<Option<UpgradeRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, to_version, status, finished_at, safety_point, contract_applied_at, \
                check_report \
           FROM ops_upgrade WHERE to_version = $1 ORDER BY started_at DESC LIMIT 1",
    )
    .bind(version)
    .fetch_optional(db)
    .await
}

/// Records an upgrade's start on the database. `check_report` carries where
/// the old binary was, so rollback can bring it back.
pub async fn record_start(
    db: &attome_db::DbPool,
    from_version: &str,
    to_version: &str,
    safety_point: &str,
    check_report: &serde_json::Value,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO ops_upgrade (id, from_version, to_version, started_at, status, safety_point, \
                                  check_report) \
         VALUES (uuidv7(), $1, $2, now(), 'started', $3, $4) RETURNING id",
    )
    .bind(from_version)
    .bind(to_version)
    .bind(safety_point)
    .bind(check_report)
    .fetch_one(db)
    .await
}

/// Moves an upgrade to `status`; `false` when it has already moved on.
pub async fn record_status(
    db: &attome_db::DbPool,
    id: Uuid,
    from: &str,
    status: &str,
) -> Result<bool, sqlx::Error> {
    let done = sqlx::query(
        "UPDATE ops_upgrade SET status = $3, finished_at = COALESCE(finished_at, now()), \
                row_version = row_version + 1 \
          WHERE id = $1 AND status = $2",
    )
    .bind(id)
    .bind(from)
    .bind(status)
    .execute(db)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Names the point a point-in-time restore can return to.
pub async fn create_restore_point(db: &attome_db::DbPool, name: &str) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_create_restore_point($1)::text")
        .bind(name)
        .execute(db)
        .await?;
    Ok(())
}

/// Runs one contract file in its own transaction, waiting at most five seconds
/// for a lock, so it cannot wedge live traffic. The file is recorded in that
/// transaction, which closes rollback; `false` when an earlier run did it.
#[expect(
    clippy::disallowed_methods,
    reason = "a command-line step, not a request: the operator needs the database's own error"
)]
pub async fn run_contract_file(
    db: &attome_db::DbPool,
    upgrade: Uuid,
    file: &str,
    sql: &str,
) -> Result<bool, sqlx::Error> {
    let mut tx = db.begin().await?;
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(&mut *tx)
        .await?;
    let done: bool = sqlx::query_scalar(
        "SELECT COALESCE(check_report -> 'contract_done', '[]'::jsonb) ? $2 \
           FROM ops_upgrade WHERE id = $1 FOR UPDATE",
    )
    .bind(upgrade)
    .bind(file)
    .fetch_one(&mut *tx)
    .await?;
    if done {
        return Ok(false);
    }
    sqlx::raw_sql(sql).execute(&mut *tx).await?;
    sqlx::query(
        "UPDATE ops_upgrade SET contract_applied_at = COALESCE(contract_applied_at, now()), \
                check_report = jsonb_set(COALESCE(check_report, '{}'::jsonb), '{contract_done}', \
                    COALESCE(check_report -> 'contract_done', '[]'::jsonb) || to_jsonb($2::text)), \
                row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(upgrade)
    .bind(file)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(day: u32) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(&format!("2026-10-{day:02}T00:00:00Z"))
            .expect("a date")
            .with_timezone(&Utc)
    }

    fn file(days: u32, sha256: &str) -> ContractSql {
        ContractSql {
            file: "0400_contract_x.sql".to_owned(),
            sha256: sha256.to_owned(),
            eligible_after_days: days,
        }
    }

    fn upgrade(contract: Option<DateTime<Utc>>) -> UpgradeRow {
        UpgradeRow {
            id: Uuid::nil(),
            to_version: Some("2.0.0".to_owned()),
            status: "verified".to_owned(),
            finished_at: Some(at(1)),
            safety_point: Some("attome-upgrade-2.0.0".to_owned()),
            contract_applied_at: contract,
            check_report: None,
        }
    }

    #[test]
    fn rollback_refused_after_contract() {
        assert!(rollback_allowed(&upgrade(None), at(2)).is_ok());
        let refused = rollback_allowed(&upgrade(Some(at(8))), at(9)).expect_err("refused");
        assert!(refused.contains("attome-upgrade-2.0.0"), "{refused}");
        assert!(refused.contains("1440 minutes"), "{refused}");
    }

    #[test]
    fn contract_waits_for_hold_period() {
        let files = [file(7, "a")];
        assert!(eligible(&files, at(1), at(7)).is_empty());
        assert_eq!(eligible(&files, at(1), at(8)).len(), 1);
    }

    #[test]
    fn contract_file_hash_mismatch_refused() {
        let good = file(
            7,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
        assert_eq!(check_file(&good, b"abc"), Ok(()));
        assert!(matches!(
            check_file(&good, b"abd"),
            Err(ContractError::HashMismatch { .. })
        ));
    }
}
