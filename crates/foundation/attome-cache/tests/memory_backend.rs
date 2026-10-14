//! The in-process store runs the same primitives Redis does (A5,
//! `docs/solo-memory-backend.md`). These need no server: they exercise each
//! primitive's memory form with the assertions its Redis form's suite makes.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::time::Duration;

use attome_cache::token_window::{self, Reservation, ReserveWindow};
use attome_cache::{Store, rate_limit, sticky_primary, write_coalesce};
use uuid::Uuid;

#[tokio::test]
async fn the_rate_limiter_counts_a_sliding_window_per_key() {
    let store = Store::memory();
    let key = format!("t:rl:{}", Uuid::now_v7());
    for n in 1..=5u32 {
        let out = rate_limit::check(&store, &key, 5).await.unwrap();
        assert!(out.allowed, "request {n} is within the limit");
        assert_eq!(out.remaining, 5 - n);
    }
    let refused = rate_limit::check(&store, &key, 5).await.unwrap();
    assert!(!refused.allowed);
    assert!(refused.retry_after_secs >= 1);
    // A rejected request is not recorded: the count stays at the limit.
    let again = rate_limit::check(&store, &key, 5).await.unwrap();
    assert!(!again.allowed);
    assert_eq!(again.remaining, 0);
}

#[tokio::test]
async fn the_token_window_sums_charges_and_refunds() {
    let store = Store::memory();
    let key = format!("t:tw:{}", Uuid::now_v7());
    let window = Duration::from_secs(3600);
    assert_eq!(
        token_window::read(&store, &key, window)
            .await
            .unwrap()
            .consumed,
        0
    );
    token_window::add(&store, &key, 700, window).await.unwrap();
    token_window::add(&store, &key, 300, window).await.unwrap();
    assert_eq!(
        token_window::read(&store, &key, window)
            .await
            .unwrap()
            .consumed,
        1000
    );
    // A signed refund reduces the window and the sum clamps at zero.
    token_window::charge(&store, &key, -400, window)
        .await
        .unwrap();
    assert_eq!(
        token_window::read(&store, &key, window)
            .await
            .unwrap()
            .consumed,
        600
    );
    token_window::charge(&store, &key, -10_000, window)
        .await
        .unwrap();
    assert_eq!(
        token_window::read(&store, &key, window)
            .await
            .unwrap()
            .consumed,
        0
    );
}

#[tokio::test]
async fn reserve_all_is_all_or_nothing() {
    let store = Store::memory();
    let wide = format!("t:wide:{}", Uuid::now_v7());
    let narrow = format!("t:narrow:{}", Uuid::now_v7());
    let hour = Duration::from_secs(3600);
    let windows = [
        ReserveWindow {
            key: &wide,
            window: hour,
            limit: 1000,
        },
        ReserveWindow {
            key: &narrow,
            window: hour,
            limit: 100,
        },
    ];
    // Fits both.
    assert!(matches!(
        token_window::reserve_all(&store, &windows, 60)
            .await
            .unwrap(),
        Reservation::Reserved(_)
    ));
    // Refused by the narrow window (index 1); the wide one is not charged.
    let Reservation::Refused(refused) = token_window::reserve_all(&store, &windows, 60)
        .await
        .unwrap()
    else {
        panic!("the second reservation exceeds the narrow window");
    };
    assert_eq!(refused.index, 1);
    assert_eq!(refused.state.consumed, 60);
    assert_eq!(
        token_window::read(&store, &wide, hour)
            .await
            .unwrap()
            .consumed,
        60,
        "a refused reservation charges no window"
    );
    // An estimate larger than the whole allowance is refused however empty.
    assert!(matches!(
        token_window::reserve_all(&store, &windows[1..], 101)
            .await
            .unwrap(),
        Reservation::Refused(_)
    ));
}

#[tokio::test]
async fn write_coalesce_sums_increments_and_drains_once() {
    let store = Store::memory();
    let hash = format!("t:wc:{}", Uuid::now_v7());
    write_coalesce::incr(&store, &hash, "route-a", 1, 60)
        .await
        .unwrap();
    write_coalesce::incr(&store, &hash, "route-a", 2, 60)
        .await
        .unwrap();
    write_coalesce::incr(&store, &hash, "route-b", 5, 60)
        .await
        .unwrap();
    write_coalesce::set(&store, &hash, "touch", "latest")
        .await
        .unwrap();
    let mut drained = write_coalesce::drain(&store, &hash).await.unwrap();
    drained.sort();
    assert_eq!(
        drained,
        vec![
            ("route-a".to_owned(), "3".to_owned()),
            ("route-b".to_owned(), "5".to_owned()),
            ("touch".to_owned(), "latest".to_owned()),
        ]
    );
    assert!(
        write_coalesce::drain(&store, &hash)
            .await
            .unwrap()
            .is_empty(),
        "a drain clears the hash"
    );
}

#[tokio::test]
async fn the_read_your_writes_pin_round_trips() {
    let store = Store::memory();
    let user = Uuid::now_v7();
    assert_eq!(
        sticky_primary::check_pin(&store, user).await,
        sticky_primary::PinCheck::None
    );
    sticky_primary::pin_write_with_lsn(&store, user, "16/B374D848", 30)
        .await
        .unwrap();
    assert_eq!(
        sticky_primary::check_pin(&store, user).await,
        sticky_primary::PinCheck::Pinned("16/B374D848".to_owned())
    );
}

#[tokio::test]
async fn the_in_process_store_reports_no_persistence_alarm() {
    let store = Store::memory();
    let status = attome_cache::persistence::probe(&store).await.unwrap();
    assert!(status.policy_configured);
    let memory = attome_cache::persistence::memory_probe(&store)
        .await
        .unwrap();
    assert_eq!(memory.maxmemory_bytes, 0);
}

#[tokio::test]
async fn doorbells_reach_a_subscriber_on_the_same_store() {
    use std::sync::{Arc, Mutex};
    let (store, _) = Store::from_config(&memory_config()).await.unwrap();
    let subscriber = attome_cache::Subscriber::connect(&store, &memory_config())
        .await
        .unwrap();
    let heard = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&heard);
    subscriber.on_message(move |bell| {
        sink.lock()
            .unwrap()
            .push((bell.channel.clone(), bell.payload.clone()));
    });
    subscriber.subscribe("meta_version").await.unwrap();
    // Let the listener task reach its first await.
    tokio::task::yield_now().await;
    store.publish("meta_version", "7").await.unwrap();
    for _ in 0..50 {
        if !heard.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        heard.lock().unwrap().as_slice(),
        [("meta_version".to_owned(), Some("7".to_owned()))]
    );
}

fn memory_config() -> attome_config::AppConfig {
    let json = r#"{
        "app": { "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                 "frontend_port": 4200, "log_level": "error", "threads": 1,
                 "max_body_size_bytes": 1048576, "request_timeout_secs": 5,
                 "enable_session": true, "max_connection_num": 64,
                 "max_connection_num_per_ip": 16, "use_gzip": false,
                 "enable_compression": false, "gzip_level": 1, "br_level": 1,
                 "idle_connection_timeout": 30, "keepalive_requests": 100,
                 "static_files_cache_time": 0, "server_header_field": "attome-test" },
        "database": { "host": "localhost", "port": 5432, "dbname": "unused",
                      "user": "unused", "password": "unused", "schema": "public",
                      "connection_number": 1, "timeout": 5.0 },
        "cache": { "backend": "memory" },
        "storage": { "s3_endpoint": "http://localhost:9000", "s3_public_endpoint": "",
                     "s3_region": "us-east-1", "s3_access_key": "test", "s3_secret_key": "test",
                     "s3_bucket": "attome-test", "s3_use_path_style": true, "s3_verify_ssl": false },
        "auth": { "jwt_secret": "test-only-throwaway-secret-do-not-use-in-prod",
                  "jwt_issuer": "attome-test", "jwt_expiry_hours": 1,
                  "oauth_google_client_id": "", "oauth_google_client_secret": "" },
        "rate_limit": { "anonymous_rpm": 1000, "authenticated_rpm": 1000 },
        "observability": { "metrics_port": 0, "log_sampling_rate": 1.0,
                           "trace_sampling_rate": 1.0, "enable_distributed_tracing": false },
        "email": { "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
                   "smtp_password": "", "smtp_from_address": "t@t.local", "smtp_from_name": "t",
                   "smtp_use_tls": false, "queue_poll_seconds": 30, "max_retries": 1, "batch_size": 1 },
        "google_ai": { "api_key": "", "base_url": "https://example.invalid",
                       "default_model": "none", "timeout_seconds": 1 },
        "llm_api": {}, "external_api": {}, "s2s": { "enabled": false },
        "security": { "bootstrap_admin_email": null },
        "cors": { "allowed_origins": ["http://allowed.test"] }
    }"#;
    serde_json::from_str(json).expect("config deserialises")
}
