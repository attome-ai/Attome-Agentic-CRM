//! P-db-maintenance item (c) — create-ahead maintenance for the RANGE-partitioned
//! audit family + `s2s_access_log` (migrations/0026_audit_partitioning.sql).
//! Generic over table/column since all four partitioned tables share one monthly
//! recipe; lives here (not in attome-audit or attome-s2s) because it is a utility shared
//! by more than one xrm-* crate's tables — the caller (the website's job handler,
//! the one place both audit and s2s tables are visible) supplies the specific list.
//!
//! Archive/drop of old partitions is deliberately NOT here — gated on
//! P-data-lifecycle's erasure ruling, ships later, config-off (plan §5 step 7).

use attome_db::DbPool;
use attome_types::AppError;
use chrono::{Datelike, Utc};

/// Same charset as `attome_metadata::provision::valid_identifier`, from the shared
/// `attome_db::ident` validator (CLEANUP-REVIEW 3.4). No length cap here: the
/// callers pass fixed table/column constants, never request data, and this
/// check has never capped them.
fn valid_identifier(s: &str) -> bool {
    attome_db::ident::is_identifier(s)
}

/// Idempotently creates any missing monthly partitions for `table` (already
/// `PARTITION BY RANGE (partition_col)`) from the current calendar month through
/// `months_ahead` months out. Returns how many partitions were newly created —
/// `0` on a re-run once caught up, which is the steady state.
#[expect(
    clippy::expect_used,
    reason = "the first day of a month at midnight is always a valid timestamp"
)]
pub async fn ensure_ahead_partitions(
    db: &DbPool,
    table: &str,
    partition_col: &str,
    storage_params: &str,
    months_ahead: u32,
) -> Result<u32, AppError> {
    if !valid_identifier(table) || !valid_identifier(partition_col) {
        return Err(AppError::internal(format!(
            "invalid identifier: table={table}, partition_col={partition_col}"
        )));
    }

    let now = Utc::now();
    let cutover = now
        .date_naive()
        .with_day(1)
        .expect("day 1 is always valid")
        .and_hms_opt(0, 0, 0)
        .expect("midnight is always valid")
        .and_utc();

    let mut created = 0u32;
    for i in 0..=months_ahead {
        let part_start = add_months(cutover, i);
        let part_end = add_months(cutover, i + 1);
        let part_name = format!("{table}_p{}", part_start.format("%Y_%m"));

        // Checked before creating (rather than inferred from CREATE TABLE IF NOT
        // EXISTS's rows_affected, which is always 0 for DDL either way) so the
        // returned count reflects partitions actually created this call, not a
        // steady-state no-op re-run. Filtered by current_schema(), not a bare
        // ::regclass cast — that cast errors on a not-yet-existing name instead
        // of returning false, which is exactly the case being checked for.
        let already_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1 FROM pg_class c
                 JOIN pg_namespace n ON n.oid = c.relnamespace
                 WHERE n.nspname = current_schema() AND c.relname = $1
             )",
        )
        .bind(&part_name)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;

        if already_exists {
            continue;
        }

        // CREATE TABLE ... PARTITION OF is DDL, not DML — no bind parameters for
        // the FOR VALUES bounds, so they're formatted as ISO-8601 literals
        // (unambiguous, no locale/injection surface — these are computed
        // timestamps, never request data).
        let sql = format!(
            r#"CREATE TABLE IF NOT EXISTS "{part_name}" PARTITION OF "{table}"
                   FOR VALUES FROM ('{}') TO ('{}') WITH ({storage_params})"#,
            part_start.to_rfc3339(),
            part_end.to_rfc3339(),
        );

        match sqlx::query(&sql).execute(db).await {
            Ok(_) => created += 1,
            // SQLSTATE 42P17 ("would overlap partition ...") — the target range is
            // already covered by a differently-named partition. This is expected
            // and benign for the current month right after migration 0026 runs:
            // that migration's historical partition (`{table}_pre_partition`)
            // covers everything through its own cutover (the month *after* the
            // one it ran in), so a name-based existence check above sees no
            // `{table}_p{YYYY_MM}` for the current month and would otherwise try
            // to create one here — colliding with the historical partition's
            // range. Verified empirically against attomedb_test (the exact
            // SQLSTATE this guards) rather than assumed.
            Err(sqlx::Error::Database(ref db_err)) if db_err.code().as_deref() == Some("42P17") => {
                tracing::debug!(table = %table, partition = %part_name, "partition create-ahead: range already covered by an existing partition, skipping");
            }
            Err(e) => {
                tracing::error!(error = %e, table = %table, partition = %part_name, "partition create-ahead failed");
                return Err(AppError::internal(e));
            }
        }
    }

    // Audit 10/10 plan, Phase 1.3 (invariant I11) — a partition created here
    // inherits the creating role's default privileges (migrations/0042's
    // `ALTER DEFAULT PRIVILEGES … GRANT … UPDATE, DELETE … TO
    // attome_runtime`), which are wider than an append-only parent's
    // (migrations/0098 revokes UPDATE/DELETE on the parent only). Runs on
    // every call, not only when something was created, so a partition made
    // before this existed is narrowed too.
    mirror_parent_runtime_privileges(db, table).await?;

    Ok(created)
}

/// The DML-only role whose partition privileges must never exceed the
/// parent's. Created NOLOGIN in every database by migrations/0042 (D-117).
const RUNTIME_ROLE: &str = "attome_runtime";

/// Revokes UPDATE/DELETE from [`RUNTIME_ROLE`] on every child partition of
/// `table` where the role holds a privilege the partitioned parent denies
/// it. PostgreSQL checks direct DML against a child partition using the
/// child's own ACL, not the parent's, so without this an append-only
/// parent's REVOKE is bypassed by naming the partition instead.
///
/// Generic by construction: it compares against the parent's actual
/// privileges, so an append-only table needs no entry in any list here, and a
/// table whose parent still grants UPDATE/DELETE is left untouched.
///
/// Fails when a REVOKE did not take effect (PostgreSQL only warns when the
/// executing role is neither the owner nor the grantor), so the partition
/// job fails visibly instead of leaving a writable partition behind. Must run
/// as the partition owner — the migrator pool in production, which creates
/// these partitions — or a superuser. Returns how many partitions were
/// narrowed.
pub async fn mirror_parent_runtime_privileges(db: &DbPool, table: &str) -> Result<u32, AppError> {
    if !valid_identifier(table) {
        return Err(AppError::internal(format!(
            "invalid identifier: table={table}"
        )));
    }

    let role_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
            .bind(RUNTIME_ROLE)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
    if !role_exists {
        return Ok(0);
    }

    let children = wider_than_parent(db, table, None).await?;

    let mut narrowed = 0u32;
    for child in children {
        let privileges = match (child.revoke_update, child.revoke_delete) {
            (true, true) => "UPDATE, DELETE",
            (true, false) => "UPDATE",
            (false, true) => "DELETE",
            (false, false) => continue,
        };
        if !valid_identifier(&child.relname) {
            return Err(AppError::internal(format!(
                "invalid partition identifier: {}",
                child.relname
            )));
        }

        // REVOKE is a utility statement, so nothing can be bound: the
        // partition name comes from pg_class and passed `valid_identifier`,
        // and the privilege list and role are fixed literals.
        let sql = format!(
            r#"REVOKE {privileges} ON "{}" FROM {RUNTIME_ROLE}"#,
            child.relname
        );
        sqlx::query(&sql)
            .execute(db)
            .await
            .map_err(AppError::internal)?;

        if !wider_than_parent(db, table, Some(&child.relname))
            .await?
            .is_empty()
        {
            tracing::error!(table = %table, partition = %child.relname, "partition privileges still wider than the parent after REVOKE — the executing role is neither owner nor grantor");
            return Err(AppError::internal(format!(
                "REVOKE {privileges} on partition {} from {RUNTIME_ROLE} did not take effect",
                child.relname
            )));
        }

        tracing::info!(table = %table, partition = %child.relname, privileges, "partition runtime privileges narrowed to the parent's");
        narrowed += 1;
    }

    Ok(narrowed)
}

#[derive(sqlx::FromRow)]
struct WiderChild {
    relname: String,
    revoke_update: bool,
    revoke_delete: bool,
}

/// Child partitions of `table` (optionally just `only`) on which
/// [`RUNTIME_ROLE`] holds UPDATE or DELETE that the partitioned parent does
/// not grant it.
async fn wider_than_parent(
    db: &DbPool,
    table: &str,
    only: Option<&str>,
) -> Result<Vec<WiderChild>, AppError> {
    sqlx::query_as(
        "SELECT relname, revoke_update, revoke_delete FROM (
             SELECT c.relname,
                    has_table_privilege($2::name, c.oid, 'UPDATE')
                        AND NOT has_table_privilege($2::name, p.oid, 'UPDATE') AS revoke_update,
                    has_table_privilege($2::name, c.oid, 'DELETE')
                        AND NOT has_table_privilege($2::name, p.oid, 'DELETE') AS revoke_delete
             FROM pg_inherits i
             JOIN pg_class c ON c.oid = i.inhrelid
             JOIN pg_class p ON p.oid = i.inhparent
             JOIN pg_namespace n ON n.oid = p.relnamespace
             WHERE n.nspname = current_schema()
               AND p.relname = $1
               AND p.relkind = 'p'
               AND ($3::text IS NULL OR c.relname = $3)
         ) children
         WHERE revoke_update OR revoke_delete
         ORDER BY relname",
    )
    .bind(table)
    .bind(RUNTIME_ROLE)
    .bind(only)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

// ── Archive/drop (P-retention-archive-completion §3b) ───────────────────────
//
// The create-ahead helper above only ever adds partitions; everything below
// removes them, gated on an explicit `retention.{audit,s2s_access_log}_days`
// window (default `None` = keep forever, unchanged from today) and the
// propose -> approve -> execute workflow attome-server's `retention_admin`/
// `retention` modules drive (§3e — no automatic execution exists anywhere in
// this file).

/// One partition of `table` eligible for archive/drop: its exclusive upper
/// bound is entirely in the past relative to some cutoff. Read from
/// Postgres's own catalog (`pg_inherits` + `pg_get_expr`), not derived from
/// the `{table}_p{YYYY_MM}` naming convention `ensure_ahead_partitions`
/// itself uses to *create* partitions — this also correctly covers the
/// historical `{table}_pre_partition` bucket `migrations/0026` creates,
/// which does not follow that naming convention.
#[derive(Debug, Clone)]
pub struct ArchiveCandidate {
    pub partition_name: String,
    /// Exclusive upper bound of the partition's range.
    pub upper_bound: chrono::DateTime<Utc>,
}

/// Lists `table`'s partitions whose upper bound is at or before `cutoff`. An
/// open-ended partition (`TO (MAXVALUE)` — the currently-active/future one
/// `ensure_ahead_partitions` keeps provisioned) is never a candidate. A
/// partition whose bound text this function's parser doesn't recognize is
/// logged and skipped, never guessed at.
pub async fn list_archive_candidates(
    db: &DbPool,
    table: &str,
    cutoff: chrono::DateTime<Utc>,
) -> Result<Vec<ArchiveCandidate>, AppError> {
    if !valid_identifier(table) {
        return Err(AppError::internal(format!(
            "invalid identifier: table={table}"
        )));
    }

    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT c.relname, pg_get_expr(c.relpartbound, c.oid)
           FROM pg_inherits i
           JOIN pg_class c ON c.oid = i.inhrelid
           JOIN pg_class p ON p.oid = i.inhparent
           JOIN pg_namespace n ON n.oid = p.relnamespace
          WHERE p.relname = $1 AND n.nspname = current_schema()
          ORDER BY c.relname",
    )
    .bind(table)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut candidates = Vec::new();
    for (partition_name, bound_expr) in rows {
        let Some(bound_expr) = bound_expr else {
            continue;
        };
        let Some(upper_bound) = parse_upper_bound(&bound_expr) else {
            tracing::debug!(
                table = %table,
                partition = %partition_name,
                bound = %bound_expr,
                "retention propose: could not parse partition upper bound (or it is open-ended), skipping"
            );
            continue;
        };
        if upper_bound <= cutoff {
            candidates.push(ArchiveCandidate {
                partition_name,
                upper_bound,
            });
        }
    }
    Ok(candidates)
}

/// Parses the exclusive upper bound out of a RANGE partition's
/// `pg_get_expr(relpartbound, oid)` text, e.g. `FOR VALUES FROM
/// ('2026-01-01 00:00:00+00') TO ('2026-02-01 00:00:00+00')`. Returns `None`
/// for an open upper bound (`TO (MAXVALUE)`) or any shape this parser
/// doesn't recognize.
fn parse_upper_bound(bound_expr: &str) -> Option<chrono::DateTime<Utc>> {
    let to_idx = bound_expr.rfind(" TO ")?;
    let to_part = &bound_expr[to_idx + 4..];
    if to_part.contains("MAXVALUE") {
        return None;
    }
    let start = to_part.find('\'')? + 1;
    let rest = &to_part[start..];
    let end = rest.find('\'')?;
    let raw = &rest[..end];
    chrono::DateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S%#z")
        .or_else(|_| chrono::DateTime::parse_from_rfc3339(raw))
        .map(|dt| dt.with_timezone(&Utc))
        .ok()
}

/// P-retention-archive-completion §3b step 1 — the daily proposal sweep for
/// one partitioned table: finds partitions older than `retention_days` and
/// inserts one `audit_retention_action` row per eligible partition
/// (`action_type = 'partition_archive'`). Relies on migration 0067's partial
/// unique index (`(action_type, target) WHERE status <> 'rejected'`) to make
/// the insert naturally idempotent across daily re-runs — a partition
/// already proposed, approved, executing, completed, or failed is never
/// re-proposed; a failed one is left for manual inspection (§3b.4), not
/// silently re-queued. Returns how many rows were newly proposed.
pub async fn propose_partition_archive_actions(
    db: &DbPool,
    table: &str,
    retention_days: u32,
) -> Result<u32, AppError> {
    let cutoff = Utc::now() - chrono::Duration::days(retention_days as i64);
    let candidates = list_archive_candidates(db, table, cutoff).await?;

    let mut proposed = 0u32;
    for candidate in candidates {
        let result = sqlx::query(
            "INSERT INTO audit_retention_action (action_type, target, status)
             VALUES ('partition_archive', $1, 'proposed')
             ON CONFLICT (action_type, target) WHERE status <> 'rejected' DO NOTHING",
        )
        .bind(&candidate.partition_name)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
        if result.rows_affected() > 0 {
            proposed += 1;
        }
    }
    Ok(proposed)
}

/// Metadata-only, no data movement (§3b.3 step 1) — `DETACH PARTITION` makes
/// `partition_name` an ordinary standalone table no longer part of `table`'s
/// partition set. Postgres has no live query path to it afterward, so a
/// caller that fails a later step (archive export, verification) can safely
/// leave it detached-but-undropped for manual inspection rather than losing
/// it (§3b.4/§8 "fail safe, not fail silent").
pub async fn detach_partition(
    db: &DbPool,
    table: &str,
    partition_name: &str,
) -> Result<(), AppError> {
    if !valid_identifier(table) || !valid_identifier(partition_name) {
        return Err(AppError::internal(format!(
            "invalid identifier: table={table}, partition={partition_name}"
        )));
    }
    let sql = format!(r#"ALTER TABLE "{table}" DETACH PARTITION "{partition_name}""#);
    sqlx::query(&sql)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

/// Irreversible — the caller must only call this after verifying the
/// detached partition's archive export (row count + checksum, §3b.3 step 3).
pub async fn drop_detached_partition(db: &DbPool, partition_name: &str) -> Result<(), AppError> {
    if !valid_identifier(partition_name) {
        return Err(AppError::internal(format!(
            "invalid identifier: partition={partition_name}"
        )));
    }
    let sql = format!(r#"DROP TABLE "{partition_name}""#);
    sqlx::query(&sql)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

/// Row count of a (possibly already-detached, now-standalone) partition
/// table — used to verify an archive export before `drop_detached_partition`
/// runs. A full-table `COUNT(*)` is acceptable here specifically because
/// this runs once, on one month's worth of a partition already being
/// archived away, never on a hot/live table.
pub async fn count_partition_rows(db: &DbPool, partition_name: &str) -> Result<i64, AppError> {
    if !valid_identifier(partition_name) {
        return Err(AppError::internal(format!(
            "invalid identifier: partition={partition_name}"
        )));
    }
    let sql = format!(r#"SELECT COUNT(*) FROM "{partition_name}""#);
    let count: i64 = sqlx::query_scalar(&sql)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    Ok(count)
}

#[expect(
    clippy::expect_used,
    reason = "the first day of a computed month at midnight is always a valid timestamp"
)]
fn add_months(t: chrono::DateTime<Utc>, months: u32) -> chrono::DateTime<Utc> {
    let total = t.year() as i64 * 12 + (t.month0() as i64) + months as i64;
    let year = (total.div_euclid(12)) as i32;
    let month0 = total.rem_euclid(12) as u32;
    chrono::NaiveDate::from_ymd_opt(year, month0 + 1, 1)
        .expect("computed y/m is always valid")
        .and_hms_opt(0, 0, 0)
        .expect("midnight is always valid")
        .and_utc()
}

// ── Tests ─────────────────────────────────────────────────────────────────
//
// `parse_upper_bound` is pure text parsing over `pg_get_expr`'s output
// shape — exercised directly here with no database required. Everything
// else in this module's archive/drop half needs a live partitioned table
// (`ArchiveCandidate`/`propose_partition_archive_actions`/`detach_partition`/
// `drop_detached_partition`/`count_partition_rows`) and is NOT covered by
// this crate's unit tests; see the integration test file this plan adds
// under `crates/xrm/attome-core/tests/` for the live-Postgres coverage
// this needs (marked as requiring a database this sandbox does not have).
#[cfg(test)]
mod tests {
    use super::parse_upper_bound;
    use chrono::TimeZone;

    #[test]
    fn parses_a_normal_monthly_partition_bound() {
        let bound = "FOR VALUES FROM ('2026-01-01 00:00:00+00') TO ('2026-02-01 00:00:00+00')";
        let parsed = parse_upper_bound(bound).expect("must parse a well-formed bound");
        assert_eq!(
            parsed,
            chrono::Utc.with_ymd_and_hms(2026, 2, 1, 0, 0, 0).unwrap()
        );
    }

    #[test]
    fn parses_the_historical_pre_partition_bound_with_a_minvalue_lower_bound() {
        let bound = "FOR VALUES FROM (MINVALUE) TO ('2026-01-01 00:00:00+00')";
        let parsed = parse_upper_bound(bound).expect("MINVALUE lower bound must not block parsing");
        assert_eq!(
            parsed,
            chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
        );
    }

    #[test]
    fn an_open_ended_maxvalue_upper_bound_is_never_a_candidate() {
        let bound = "FOR VALUES FROM ('2026-02-01 00:00:00+00') TO (MAXVALUE)";
        assert_eq!(parse_upper_bound(bound), None);
    }

    #[test]
    fn an_unrecognized_shape_is_skipped_rather_than_guessed_at() {
        assert_eq!(parse_upper_bound("garbage"), None);
        assert_eq!(parse_upper_bound(""), None);
    }

    /// CLEANUP-REVIEW 3.4: accept/reject set unchanged by the move to
    /// `attome_db::ident` — leading underscore allowed, no length cap.
    #[test]
    fn identifier_accept_reject_set() {
        use super::valid_identifier;
        for ok in ["audit_log", "_p", "created_on", "t_p2026_01"] {
            assert!(valid_identifier(ok), "{ok}");
        }
        assert!(valid_identifier(&"a".repeat(200)));
        for bad in ["", "Audit", "1t", "a-b", "a b", "a.b", "a\"b", "é"] {
            assert!(!valid_identifier(bad), "{bad:?}");
        }
    }
}
