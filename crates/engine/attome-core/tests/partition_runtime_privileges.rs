//! Audit 10/10 plan Phase 1.3 (invariant I11): a child partition never grants
//! `attome_runtime` more than its partitioned parent.
//!
//! PostgreSQL checks direct DML against a partition using the partition's own
//! ACL. Migration 0098 revokes UPDATE/DELETE on the append-only ledger
//! *parents* only, and 0042's default privileges give runtime UPDATE/DELETE on
//! every partition `attome_migrator` creates. Migration 0470 narrows existing
//! partitions; `ensure_ahead_partitions` narrows the ones created later.
//!
//! Execution rule 3 of the plan: every permission assertion runs on a real
//! login as `attome_runtime`, never through the owner or superuser connection,
//! which would bypass the grants under test. The new partition is created by a
//! real `attome_migrator` login, the role production's partition job uses.
//!
//! Also holds register item A-3 (contract C2): runtime may insert an approval
//! grant and record its digest, but not rewrite or delete it (migration 0473).
//!
//! Needs a database migrated through 0473. Sets LOGIN passwords on the two
//! cluster roles, as `crates/server/tests/db_role_seed.rs` does.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-core --test partition_runtime_privileges -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::str::FromStr;
use uuid::Uuid;

const LEDGER_PARENTS: [&str; 3] = ["audit_header", "audit_detail", "audit_snapshot"];

const STORAGE_PARAMS: &str = "fillfactor = 100, autovacuum_vacuum_insert_scale_factor = 0.02, autovacuum_vacuum_scale_factor = 0.05, autovacuum_vacuum_cost_delay = 2";

async fn owner_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

/// Gives `role` a fresh LOGIN password (through the owner connection) and
/// returns a pool that authenticates as that role against the same database.
async fn login_as(owner: &DbPool, role: &str) -> DbPool {
    let password = format!("p13-{}", Uuid::now_v7().simple());
    // Utility statement: no bind parameters. `role` is a fixed literal from
    // this file and the password is hex from a UUID.
    sqlx::query(&format!(
        "ALTER ROLE {role} WITH LOGIN PASSWORD '{password}'"
    ))
    .execute(owner)
    .await
    .unwrap_or_else(|e| panic!("set a LOGIN password on {role}: {e}"));

    let url = attome_testkit::migrated_db_url().expect("checked by owner_db");
    let options = PgConnectOptions::from_str(&url)
        .expect("DATABASE_URL must be a valid postgres:// URL")
        .username(role)
        .password(&password);
    PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap_or_else(|e| panic!("{role} must authenticate with the password just set: {e}"))
}

fn sqlstate(err: &sqlx::Error) -> Option<String> {
    err.as_database_error()
        .and_then(|e| e.code())
        .map(|c| c.into_owned())
}

/// Asserts `runtime` cannot UPDATE or DELETE `partition` by naming it
/// directly: both statements fail with 42501 (insufficient_privilege).
/// Privileges are checked before any row is matched, so no data is needed.
async fn assert_runtime_cannot_mutate(runtime: &DbPool, partition: &str) {
    for sql in [
        format!(r#"UPDATE "{partition}" SET created_at = created_at WHERE id = $1"#),
        format!(r#"DELETE FROM "{partition}" WHERE id = $1"#),
    ] {
        let err = sqlx::query(&sql)
            .bind(Uuid::nil())
            .execute(runtime)
            .await
            .expect_err(&format!(
                "attome_runtime must not be able to run `{sql}` against partition {partition}"
            ));
        assert_eq!(
            sqlstate(&err).as_deref(),
            Some("42501"),
            "`{sql}` must fail on privileges, not for another reason: {err}"
        );
    }
}

#[tokio::test]
async fn runtime_cannot_update_or_delete_existing_ledger_partitions_by_name() {
    let owner = skip_if_no_db!(owner_db().await);
    let runtime = login_as(&owner, "attome_runtime").await;

    let children: Vec<(String, String)> = sqlx::query_as(
        "SELECT p.relname::text, c.relname::text
         FROM pg_inherits i
         JOIN pg_class c ON c.oid = i.inhrelid
         JOIN pg_class p ON p.oid = i.inhparent
         JOIN pg_namespace n ON n.oid = p.relnamespace
         WHERE n.nspname = current_schema()
           AND p.relname = ANY($1)
         ORDER BY 1, 2",
    )
    .bind(LEDGER_PARENTS.as_slice())
    .fetch_all(&owner)
    .await
    .expect("list ledger partitions");

    for parent in LEDGER_PARENTS {
        assert!(
            children.iter().any(|(p, _)| p == parent),
            "{parent} must have at least one partition for this test to mean anything"
        );
    }

    for (parent, child) in &children {
        assert_runtime_cannot_mutate(&runtime, child).await;
        eprintln!("verified as attome_runtime: {parent} -> {child} refuses UPDATE and DELETE");
    }

    runtime.close().await;
}

#[tokio::test]
async fn a_partition_the_migrator_creates_after_the_migration_is_narrowed_by_ensure_ahead_partitions()
 {
    let owner = skip_if_no_db!(owner_db().await);
    let migrator = login_as(&owner, "attome_migrator").await;
    let runtime = login_as(&owner, "attome_runtime").await;

    // Far outside any create-ahead window, so this test owns the partition.
    let parent = "audit_detail";
    let partition = "audit_detail_p2099_01";
    sqlx::query(&format!(r#"DROP TABLE IF EXISTS "{partition}""#))
        .execute(&owner)
        .await
        .expect("clear a leftover partition from an earlier run");

    // Created by the migrator login, the same DDL shape ensure_ahead_partitions
    // issues, so 0042's default privileges apply exactly as in production.
    sqlx::query(&format!(
        r#"CREATE TABLE "{partition}" PARTITION OF "{parent}"
               FOR VALUES FROM ('2099-01-01T00:00:00+00:00') TO ('2099-02-01T00:00:00+00:00')
               WITH ({STORAGE_PARAMS})"#
    ))
    .execute(&migrator)
    .await
    .expect("attome_migrator creates a new ledger partition");

    let privileges = |partition: &'static str| {
        let owner = owner.clone();
        async move {
            sqlx::query_as::<_, (bool, bool, bool)>(
                "SELECT has_table_privilege('attome_runtime', c.oid, 'UPDATE'),
                        has_table_privilege('attome_runtime', c.oid, 'DELETE'),
                        pg_get_userbyid(c.relowner) = 'attome_migrator'
                 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                 WHERE n.nspname = current_schema() AND c.relname = $1",
            )
            .bind(partition)
            .fetch_one(&owner)
            .await
            .expect("read partition privileges")
        }
    };

    // Control: the hole this test guards is real before the job runs.
    let (can_update, can_delete, migrator_owned) = privileges(partition).await;
    assert!(
        migrator_owned,
        "the partition must be owned by attome_migrator"
    );
    assert!(
        can_update && can_delete,
        "control: a migrator-created partition must start out granting runtime \
         UPDATE/DELETE (0042 default privileges), or this test proves nothing"
    );
    sqlx::query(&format!(
        r#"UPDATE "{partition}" SET created_at = created_at WHERE id = $1"#
    ))
    .bind(Uuid::nil())
    .execute(&runtime)
    .await
    .expect("control: attome_runtime CAN update the partition before mirroring");

    // The production path, run as the migrator login like the partition job.
    attome_core::partition_maintenance::ensure_ahead_partitions(
        &migrator,
        parent,
        "created_at",
        STORAGE_PARAMS,
        0,
    )
    .await
    .expect("ensure_ahead_partitions as attome_migrator");

    let (can_update, can_delete, _) = privileges(partition).await;
    assert!(
        !can_update && !can_delete,
        "after ensure_ahead_partitions the partition must not grant runtime UPDATE/DELETE"
    );
    assert_runtime_cannot_mutate(&runtime, partition).await;

    let parent_insert: bool =
        sqlx::query_scalar("SELECT has_table_privilege('attome_runtime', $1::regclass, 'INSERT')")
            .bind(parent)
            .fetch_one(&owner)
            .await
            .expect("read parent INSERT privilege");
    assert!(
        parent_insert,
        "runtime must still be able to INSERT through the parent"
    );

    let narrowed_again =
        attome_core::partition_maintenance::mirror_parent_runtime_privileges(&migrator, parent)
            .await
            .expect("second mirroring pass");
    assert_eq!(narrowed_again, 0, "mirroring is idempotent");

    runtime.close().await;
    migrator.close().await;
    sqlx::query(&format!(r#"DROP TABLE IF EXISTS "{partition}""#))
        .execute(&owner)
        .await
        .expect("drop the test partition");
}

/// Audit 10/10 register A-3 (contract C2), migration 0473: runtime may insert
/// an approval grant and record its decision digest (the `signature` column,
/// written by `attome_audit::signoff::record_decision_digest`), but cannot
/// rewrite any column the digest is computed from, nor delete the row.
#[tokio::test]
async fn runtime_can_insert_a_grant_and_record_its_digest_but_cannot_rewrite_or_delete_it() {
    let owner = skip_if_no_db!(owner_db().await);
    let runtime = login_as(&owner, "attome_runtime").await;

    let request_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO approval_request (id, action_type, payload, requested_by, expires_at)
         VALUES ($1, 'audit.a3_test', '{}'::jsonb, $2, NOW() + INTERVAL '1 hour')",
    )
    .bind(request_id)
    .bind(Uuid::now_v7())
    .execute(&owner)
    .await
    .expect("owner seeds an approval request");

    // The legitimate runtime writes: attome_approval's INSERT, then the exact
    // UPDATE statement record_decision_digest issues.
    let grant_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO approval_grant (id, request_id, approver_id, decision, decided_at)
         VALUES ($1, $2, $3, 'approved', NOW())",
    )
    .bind(grant_id)
    .bind(request_id)
    .bind(Uuid::now_v7())
    .execute(&runtime)
    .await
    .expect("attome_runtime must still INSERT a grant (attome_approval::decide)");

    let updated = sqlx::query("UPDATE approval_grant SET signature = $1::jsonb WHERE id = $2")
        .bind(serde_json::json!({"algo": "sha256-v1", "digest": "a3"}))
        .bind(grant_id)
        .execute(&runtime)
        .await
        .expect("attome_runtime must still record the decision digest");
    assert_eq!(
        updated.rows_affected(),
        1,
        "the digest write must hit the grant row"
    );

    for set in [
        "decision = 'rejected'",
        "approver_id = gen_random_uuid()",
        "decided_at = NOW()",
        "step = step + 1",
        "decided_by = gen_random_uuid()",
        "on_behalf_of = gen_random_uuid()",
        "request_id = request_id",
        "id = id",
    ] {
        let sql = format!("UPDATE approval_grant SET {set} WHERE id = $1");
        let err = sqlx::query(&sql)
            .bind(grant_id)
            .execute(&runtime)
            .await
            .expect_err(&format!("attome_runtime must not be able to run `{sql}`"));
        assert_eq!(
            sqlstate(&err).as_deref(),
            Some("42501"),
            "`{sql}` must fail on privileges, not for another reason: {err}"
        );
    }

    let err = sqlx::query("DELETE FROM approval_grant WHERE id = $1")
        .bind(grant_id)
        .execute(&runtime)
        .await
        .expect_err("attome_runtime must not be able to delete a grant");
    assert_eq!(
        sqlstate(&err).as_deref(),
        Some("42501"),
        "DELETE must fail on privileges, not for another reason: {err}"
    );

    let (decision, digest): (String, Option<String>) =
        sqlx::query_as("SELECT decision, signature->>'digest' FROM approval_grant WHERE id = $1")
            .bind(grant_id)
            .fetch_one(&owner)
            .await
            .expect("the grant row is still there");
    assert_eq!(decision, "approved", "the refused rewrite changed nothing");
    assert_eq!(digest.as_deref(), Some("a3"), "the digest write persisted");

    runtime.close().await;
    sqlx::query("DELETE FROM approval_grant WHERE id = $1")
        .bind(grant_id)
        .execute(&owner)
        .await
        .expect("owner removes the test grant");
    sqlx::query("DELETE FROM approval_request WHERE id = $1")
        .bind(request_id)
        .execute(&owner)
        .await
        .expect("owner removes the test request");
}
