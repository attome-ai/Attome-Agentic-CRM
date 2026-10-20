//! E14-T5: the web event batch writer against a real database — a batch
//! written twice changes nothing the second time, the session counts its
//! page views once and keeps its first UTM values, and office networks and
//! disabled sites write nothing.
//!
//! `marketing_tracked_site` is provisioned here (the marketing pack
//! provisions it on a deployment); fixture rows are direct SQL against this
//! binary's throwaway database (guidelines §4's test exemption).
//!
//! ```powershell
//! .\scripts\run-integration-tests.ps1 -TestArgs "-p attome-marketing --test web_event_batch"
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test seeds fixtures on the raw pool"
)]

use attome_marketing::tracking::writer::{WebEventBatch, write_batch};
use attome_testkit::skip_if_no_db;
use chrono::{Duration, SecondsFormat, Utc};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

async fn test_db() -> Option<PgPool> {
    let db = attome_testkit::migrated_pool(5).await?;
    let id = attome_metadata::provision::ensure_entity(
        &db,
        "marketing_tracked_site",
        "marketing_tracked_site",
        None,
        false,
    )
    .await
    .expect("ensure marketing_tracked_site");
    for (field, field_type) in [
        ("site_key", "text"),
        ("office_networks", "text"),
        ("enabled", "bool"),
    ] {
        attome_metadata::provision::ensure_attribute(
            &db, id, field, field, field_type, false, false, false, true, None, None,
        )
        .await
        .unwrap_or_else(|e| panic!("ensure marketing_tracked_site.{field}: {e}"));
    }
    Some(db)
}

/// A new site; returns its key.
async fn site(db: &PgPool, enabled: bool, office_networks: &str) -> String {
    let key = format!("site-{}", Uuid::now_v7().simple());
    sqlx::query(
        "INSERT INTO marketing_tracked_site (site_key, office_networks, enabled) VALUES ($1, $2, $3)",
    )
    .bind(&key)
    .bind(office_networks)
    .bind(enabled)
    .execute(db)
    .await
    .expect("insert tracked site");
    key
}

fn at(seconds_ago: i64) -> String {
    (Utc::now() - Duration::seconds(seconds_ago)).to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn batch(site_key: &str, session: Uuid, events: Value) -> WebEventBatch {
    WebEventBatch {
        site_key: site_key.into(),
        ip_prefix: "203.0.113.0".into(),
        country: Some("sa".into()),
        user_agent_class: "desktop".into(),
        batch: json!({
            "site": site_key,
            "visitor": Uuid::now_v7().to_string(),
            "session": session.to_string(),
            "events": events,
        }),
    }
}

async fn session_row(db: &PgPool, session: Uuid) -> Option<(i32, Option<String>, Option<String>)> {
    sqlx::query_as(
        "SELECT page_count, utm_source, landing_url FROM marketing_web_session WHERE id = $1",
    )
    .bind(session)
    .fetch_optional(db)
    .await
    .expect("read session")
}

async fn event_count(db: &PgPool, session: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM marketing_web_event WHERE session_id = $1")
        .bind(session)
        .fetch_one(db)
        .await
        .expect("count events")
}

#[tokio::test]
async fn a_batch_written_twice_changes_nothing_the_second_time() {
    let db = skip_if_no_db!(test_db().await);
    let key = site(&db, true, "").await;
    let session = Uuid::now_v7();
    let first = batch(
        &key,
        session,
        json!([
            {"kind": "page_view", "at": at(60), "url": "https://x.test/", "title": "Home",
             "landing": {"utm_source": "newsletter", "gclid": "g1"}},
            {"kind": "page_view", "at": at(30), "url": "https://x.test/pricing", "title": "Pricing"},
            {"kind": "page_leave", "at": at(20), "url": "https://x.test/pricing", "time_on_page_ms": 10000}
        ]),
    );

    let counts = write_batch(&db, &first).await.expect("first run");
    assert_eq!(counts.written, 3);
    assert_eq!(counts.duplicates, 0);
    let again = write_batch(&db, &first).await.expect("second run");
    assert_eq!(again.written, 0);
    assert_eq!(again.duplicates, 3);
    assert_eq!(event_count(&db, session).await, 3);
    assert_eq!(
        session_row(&db, session).await,
        Some((2, Some("newsletter".into()), Some("https://x.test/".into()))),
        "two page views, counted once"
    );

    // A later batch with other UTM values adds its page view and keeps the
    // session's first landing.
    let later = batch(
        &key,
        session,
        json!([
            {"kind": "page_view", "at": at(5), "url": "https://x.test/demo",
             "landing": {"utm_source": "ads"}}
        ]),
    );
    write_batch(&db, &later).await.expect("later batch");
    assert_eq!(
        session_row(&db, session).await,
        Some((3, Some("newsletter".into()), Some("https://x.test/".into())))
    );
}

#[tokio::test]
async fn office_networks_bots_and_disabled_sites_write_nothing() {
    let db = skip_if_no_db!(test_db().await);
    let events = json!([{"kind": "page_view", "at": at(10), "url": "https://x.test/"}]);

    let office = site(&db, true, "203.0.113.0/24").await;
    let session = Uuid::now_v7();
    let counts = write_batch(&db, &batch(&office, session, events.clone()))
        .await
        .expect("office batch");
    assert_eq!(counts.dropped_office, 1);
    assert_eq!(event_count(&db, session).await, 0);
    assert_eq!(session_row(&db, session).await, None);

    let open = site(&db, true, "").await;
    let session = Uuid::now_v7();
    let mut crawler = batch(&open, session, events.clone());
    crawler.user_agent_class = "Mozilla/5.0 (compatible; Googlebot/2.1)".into();
    let counts = write_batch(&db, &crawler).await.expect("bot batch");
    assert_eq!(counts.dropped_bot, 1);
    assert_eq!(event_count(&db, session).await, 0);

    let disabled = site(&db, false, "").await;
    let session = Uuid::now_v7();
    let counts = write_batch(&db, &batch(&disabled, session, events))
        .await
        .expect("disabled batch");
    assert_eq!(counts.dropped_invalid, 1);
    assert_eq!(event_count(&db, session).await, 0);
}
