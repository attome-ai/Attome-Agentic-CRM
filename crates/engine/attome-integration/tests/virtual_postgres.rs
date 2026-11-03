//! L8-T2: an outside Postgres table as a virtual entity. The table lives in
//! this process's throwaway database; the source reads it through its own
//! read-only sessions, filters with typed binds, pages by offset and opens a
//! record by its uuid key.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_core::filter::Filter;
use attome_integration::connector::adapters::virtual_sources::PostgresSource;
use attome_records::virtual_entity::{VirtualProvider, VirtualQuery};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn outside_table_lists_filters_and_opens() {
    let Some(url) = attome_testkit::test_db_url() else {
        return;
    };
    let admin = sqlx::PgPool::connect(&url).await.unwrap();
    let table = format!("erp_customer_{}", Uuid::now_v7().simple());
    sqlx::query(&format!(
        "CREATE TABLE {table} (id uuid PRIMARY KEY, name text NOT NULL, amount numeric, city text)"
    ))
    .execute(&admin)
    .await
    .unwrap();
    let mut ids = Vec::new();
    for (name, amount, city) in [
        ("Alpha", 3, "Riyadh"),
        ("Beta", 7, "Jeddah"),
        ("Gamma", 12, "Riyadh"),
        ("Delta_50%", 20, "Cairo"),
    ] {
        let id = Uuid::now_v7();
        sqlx::query(&format!(
            "INSERT INTO {table} (id, name, amount, city) VALUES ($1, $2, $3::numeric, $4)"
        ))
        .bind(id)
        .bind(name)
        .bind(i64::from(amount))
        .bind(city)
        .execute(&admin)
        .await
        .unwrap();
        ids.push(id);
    }

    let source = PostgresSource::new(&url, &table, "id", &["name", "amount", "city"]).unwrap();
    let query = |filters: Vec<Filter>, page_size: i64, cursor: Option<String>| VirtualQuery {
        filters,
        sort: Some(("amount".into(), false)),
        page_size,
        cursor,
        select: None,
    };
    let over_five = Filter {
        field: "amount".into(),
        op: "gt".into(),
        value: Some(json!("5")),
    };
    let page = source
        .list(&query(vec![over_five.clone()], 2, None))
        .await
        .unwrap();
    let names: Vec<&str> = page
        .items
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        ["Beta", "Gamma"],
        "numeric comparison, sorted, one page"
    );
    let next = page.next_cursor.expect("a third row");
    let rest = source
        .list(&query(vec![over_five], 2, Some(next)))
        .await
        .unwrap();
    assert_eq!(rest.items.len(), 1);
    assert!(rest.next_cursor.is_none());

    let literal = Filter {
        field: "name".into(),
        op: "contains".into(),
        value: Some(json!("_50%")),
    };
    let found = source.list(&query(vec![literal], 50, None)).await.unwrap();
    assert_eq!(found.items.len(), 1, "% and _ are literal in contains");

    let opened = source.get(ids[2]).await.unwrap().expect("found");
    assert_eq!(opened["name"], "Gamma");
    assert_eq!(opened["id"], json!(ids[2].to_string()));
    assert!(source.get(Uuid::now_v7()).await.unwrap().is_none());
    assert!(
        !source.supports("password", "eq"),
        "only the configured fields"
    );

    sqlx::query(&format!("DROP TABLE {table}"))
        .execute(&admin)
        .await
        .unwrap();
}
