//! Z11-T16: a privilege condition written as a rule expression runs in the
//! database through the record filter; one the SQL translation cannot express
//! is refused at save, and one that stops translating denies.
//!
//! Requires a live Postgres (`DATABASE_URL`); skips when unset. Each test
//! creates its own throwaway table in the per-binary test database.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::{HashMap, HashSet};

use attome_core::AttrInfo;
use attome_security::conditions::check_expression;
use attome_security::rls::{Capability, rls_predicate_with_conditions};
use attome_server::security::{AccessLevel, ConditionOperator, GrantCondition, SecurityContext};
use attome_testkit::skip_if_no_db;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn test_db() -> Option<attome_db::DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

fn attr(name: &str, field_type_int: i32) -> AttrInfo {
    AttrInfo {
        logicalname: name.to_owned(),
        field_type_int,
        is_required: false,
        max_length: None,
        is_sensitive: false,
        is_write_restricted: false,
        is_sortable: true,
        is_filterable: true,
        lookup_entity_ref: None,
        on_target_delete: Default::default(),
        data_classification: Default::default(),
        sensitivity: Default::default(),
        sensitivity_confirmed: false,
        options: None,
    }
}

/// `amount` (number) and `status` (text).
fn attrs() -> Vec<AttrInfo> {
    vec![attr("amount", 1), attr("status", 3)]
}

fn ctx_with(privilege: &str, expression: &str) -> SecurityContext {
    let mut built = SecurityContext::human(Uuid::now_v7(), Default::default());
    built.privileges = HashSet::from([privilege.to_owned()]);
    built.condition_grants = HashMap::from([(
        privilege.to_owned(),
        vec![vec![GrantCondition {
            field_logicalname: String::new(),
            operator: ConditionOperator::Expression,
            value: serde_json::json!(expression),
            hop: None,
        }]],
    )]);
    built.role_ids = None;
    built
}

/// The ids `ctx` may read from `table` under its `deal.read` condition.
async fn visible(db: &attome_db::DbPool, table: &str, ctx: &SecurityContext) -> Vec<String> {
    let pred = rls_predicate_with_conditions(
        ctx,
        Uuid::now_v7(),
        "t",
        AccessLevel::Global,
        Capability::View,
        "deal.read",
        &attrs(),
        false,
        1,
    )
    .expect("a condition narrows a Global level");
    assert!(pred.tier_binds.is_none(), "Global: only the condition");
    let sql = format!(
        "SELECT t.name FROM \"{table}\" t WHERE TRUE {} ORDER BY t.name",
        pred.sql
    );
    let mut query = sqlx::query_scalar::<_, String>(&sql);
    for bind in &pred.condition_binds {
        query = query.bind(bind);
    }
    query.fetch_all(db).await.expect("run the filter")
}

async fn deals(db: &attome_db::DbPool) -> String {
    let table = attome_testkit::unique_logicalname("z11t16_deal");
    sqlx::query(&format!(
        "CREATE TABLE \"{table}\" (id uuid PRIMARY KEY, name text, amount numeric, status text)"
    ))
    .execute(db)
    .await
    .expect("create the table");
    for (name, amount, status) in [
        ("big-open", 500, "open"),
        ("big-won", 900, "won"),
        ("small-open", 50, "open"),
    ] {
        sqlx::query(&format!(
            "INSERT INTO \"{table}\" (id, name, amount, status) VALUES ($1, $2, $3::numeric, $4)"
        ))
        .bind(Uuid::now_v7())
        .bind(name)
        .bind(i64::from(amount))
        .bind(status)
        .execute(db)
        .await
        .expect("insert a deal");
    }
    table
}

#[tokio::test]
async fn expression_condition_filters_rows() {
    let db = skip_if_no_db!(test_db().await);
    let table = deals(&db).await;
    let ctx = ctx_with("deal.read", "amount > 100 and status == \"open\"");
    assert_eq!(visible(&db, &table, &ctx).await, vec!["big-open"]);
    let ctx = ctx_with("deal.read", "status == \"won\" or amount < 100");
    assert_eq!(
        visible(&db, &table, &ctx).await,
        vec!["big-won", "small-open"]
    );
}

#[tokio::test]
async fn untranslatable_condition_rejected() {
    // Refused at save: the clock, an unknown field, and a non-text value.
    for bad in [
        serde_json::json!("today() > amount"),
        serde_json::json!("secret == 1"),
        serde_json::json!(42),
    ] {
        assert!(check_expression(&bad, &attrs()).is_err(), "{bad}");
    }
    assert!(check_expression(&serde_json::json!("amount >= 10"), &attrs()).is_ok());

    // One that no longer translates (its field is gone) denies every row.
    let db = skip_if_no_db!(test_db().await);
    let table = deals(&db).await;
    let ctx = ctx_with("deal.read", "removed_field > 1");
    assert!(visible(&db, &table, &ctx).await.is_empty());
}

/// A path that binds the read scope as flat text (export, search) or counts
/// its placeholders (a page's LIMIT after it) sees every bind, the tier's six
/// and the condition's, in order.
#[test]
fn a_conditional_scope_counts_and_lists_every_bind() {
    let ctx = ctx_with("deal.read", "amount > 100 and status == \"open\"");
    for (level, tier) in [
        (AccessLevel::Global, 0),
        (AccessLevel::Team, attome_security::RLS_BIND_COUNT),
    ] {
        let pred = rls_predicate_with_conditions(
            &ctx,
            Uuid::now_v7(),
            "t",
            level,
            Capability::View,
            "deal.read",
            &attrs(),
            false,
            1,
        )
        .expect("a condition narrows at every level");
        assert_eq!(pred.tier_binds.is_some(), tier > 0, "{level:?}");
        assert!(!pred.condition_binds.is_empty(), "{level:?}");
        assert_eq!(pred.bind_count(), tier + pred.condition_binds.len());
        let text = pred.to_text_params();
        assert_eq!(text.len(), pred.bind_count());
        assert_eq!(text[tier..], pred.condition_binds[..]);
        assert_eq!(
            attome_security::scope_bind_count(Some(&pred)),
            pred.bind_count()
        );
    }
    assert_eq!(attome_security::scope_bind_count(None), 0);
}
