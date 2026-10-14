//! BCA-55 (attome-cache plan, closes D-153 "not verified" item 3): a pool and a
//! subscriber built from a `cache.sentinel` config follow a Sentinel failover
//! with no process restart — both a graceful `SENTINEL FAILOVER` (the old
//! master stays up and is demoted) and a crashed master.
//!
//! `#[ignore]`d because it runs its own throwaway container: one Redis master,
//! one replica and three Sentinels (quorum 2, `requirepass` on the Sentinels as
//! in `deploy/ha/sentinel.conf.example`), all in one container announcing
//! `127.0.0.1`, with every port published on loopback at the same number, so
//! the addresses Sentinel hands out are reachable from the host as-is. The
//! container is removed when the test ends, pass or fail.
//!
//! `TEST_SENTINEL_IMAGE` (default `redis:7`), `TEST_SENTINEL_BASE_PORT`
//! (default 16500; uses base, base+1 and base+10..=base+12) and
//! `TEST_SENTINEL_CONTAINER` (default `attome-bca55-sentinel`) override the
//! defaults. Needs Docker.
//!
//! ```powershell
//! cargo test -p attome-cache --test sentinel -- --ignored --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::process::Command;
use std::time::{Duration, Instant};

use attome_cache::rate_limit;
use attome_cache::redis_pool::{create_redis_pool, create_subscriber_client};
use attome_config::AppConfig;
use fred::prelude::*;
use uuid::Uuid;

const SERVICE: &str = "attome-master";

/// Detection (1 s down-after) plus election plus fred's backoff ceiling (5 s),
/// with room for a loaded host.
const FAILOVER_DEADLINE: Duration = Duration::from_secs(40);

const BASE_CONFIG_JSON: &str = r#"{
            "app": {
                "port": 0, "frontend_host": "localhost", "frontend_port": 4200,
                "log_level": "error", "threads": 1, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "idle_connection_timeout": 30,
                "keepalive_requests": 100, "static_files_cache_time": 0,
                "server_header_field": "test"
            },
            "database": {
                "host": "localhost", "port": 5555, "dbname": "unused", "user": "unused",
                "password": "unused", "schema": "public", "connection_number": 1,
                "timeout": 5.0
            },
            "cache": {
                "host": "127.0.0.1", "port": 6379, "password": "", "db": 0,
                "connection_pool_size": 2, "timeout": 2000, "l1_cache_size_mb": 1,
                "l1_cache_ttl_seconds": 60
            },
            "storage": {
                "s3_endpoint": "http://localhost:9000", "s3_region": "us-east-1",
                "s3_access_key": "test", "s3_secret_key": "test", "s3_bucket": "test"
            },
            "auth": {
                "jwt_secret": "test-only-throwaway-secret-32-bytes-min", "jwt_issuer": "test"
            },
            "rate_limit": { "anonymous_rpm": 100, "authenticated_rpm": 1000 },
            "observability": {
                "metrics_port": 0, "log_sampling_rate": 1.0, "trace_sampling_rate": 1.0,
                "enable_distributed_tracing": false
            },
            "email": {
                "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
                "smtp_password": "", "smtp_from_address": "a@b.c",
                "smtp_from_name": "t", "smtp_use_tls": false,
                "queue_poll_seconds": 5, "max_retries": 1, "batch_size": 5
            },
            "google_ai": {
                "api_key": "test", "base_url": "http://localhost",
                "default_model": "test", "timeout_seconds": 5
            }
        }"#;

struct Topology {
    container: String,
    master_port: u16,
    replica_port: u16,
    sentinel_ports: [u16; 3],
    password: String,
    sentinel_password: String,
}

impl Drop for Topology {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.container])
            .output();
    }
}

impl Topology {
    fn start() -> Self {
        let image = std::env::var("TEST_SENTINEL_IMAGE").unwrap_or_else(|_| "redis:7".into());
        let container = std::env::var("TEST_SENTINEL_CONTAINER")
            .unwrap_or_else(|_| "attome-bca55-sentinel".into());
        let base: u16 = std::env::var("TEST_SENTINEL_BASE_PORT")
            .unwrap_or_else(|_| "16500".into())
            .parse()
            .expect("TEST_SENTINEL_BASE_PORT must be a port number");
        let topology = Topology {
            container,
            master_port: base,
            replica_port: base + 1,
            sentinel_ports: [base + 10, base + 11, base + 12],
            password: Uuid::now_v7().simple().to_string(),
            sentinel_password: Uuid::now_v7().simple().to_string(),
        };
        let _ = Command::new("docker")
            .args(["rm", "-f", &topology.container])
            .output();

        let (m, r, pw, spw) = (
            topology.master_port,
            topology.replica_port,
            &topology.password,
            &topology.sentinel_password,
        );
        let server = |port: u16, extra: &str| {
            format!(
                "redis-server --port {port} --requirepass {pw} --masterauth {pw} \
                 --replica-announce-ip 127.0.0.1 --save '' --appendonly no {extra} --daemonize yes\n"
            )
        };
        let mut script = String::from("set -e\n");
        script.push_str(&server(m, ""));
        script.push_str(&server(r, &format!("--replicaof 127.0.0.1 {m}")));
        for port in topology.sentinel_ports {
            script.push_str(&format!(
                "printf '%s\\n' 'port {port}' 'protected-mode no' 'sentinel announce-ip 127.0.0.1' \
                 'sentinel monitor {SERVICE} 127.0.0.1 {m} 2' 'sentinel auth-pass {SERVICE} {pw}' \
                 'sentinel down-after-milliseconds {SERVICE} 1000' \
                 'sentinel failover-timeout {SERVICE} 2000' 'sentinel parallel-syncs {SERVICE} 1' \
                 'requirepass {spw}' > /tmp/sentinel-{port}.conf\n\
                 redis-sentinel /tmp/sentinel-{port}.conf --daemonize yes\n"
            ));
        }
        script.push_str("exec sleep infinity\n");

        let mut args: Vec<String> = vec![
            "run".into(),
            "-d".into(),
            "--name".into(),
            topology.container.clone(),
        ];
        for port in [m, r]
            .into_iter()
            .chain(topology.sentinel_ports.iter().copied())
        {
            args.push("-p".into());
            args.push(format!("127.0.0.1:{port}:{port}"));
        }
        args.extend([image, "sh".into(), "-c".into(), script]);
        let out = Command::new("docker")
            .args(&args)
            .output()
            .expect("run docker");
        assert!(
            out.status.success(),
            "docker run failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let started = Instant::now();
        loop {
            let reply = topology.sentinel(&["sentinel", "ckquorum", SERVICE]);
            if reply.starts_with("OK") {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "the Sentinel quorum never formed: {reply}"
            );
            std::thread::sleep(Duration::from_millis(500));
        }
        topology
    }

    fn cli(&self, port: u16, password: &str, args: &[&str]) -> String {
        let port = port.to_string();
        let mut full = vec![
            "exec",
            &self.container,
            "redis-cli",
            "-p",
            &port,
            "-a",
            password,
            "--no-auth-warning",
        ];
        full.extend_from_slice(args);
        let out = Command::new("docker")
            .args(&full)
            .output()
            .expect("run docker exec");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn sentinel(&self, args: &[&str]) -> String {
        self.cli(self.sentinel_ports[0], &self.sentinel_password, args)
    }

    fn server(&self, port: u16, args: &[&str]) -> String {
        self.cli(port, &self.password, args)
    }

    fn master_port_per_sentinel(&self) -> Option<u16> {
        let reply = self.sentinel(&["sentinel", "get-master-addr-by-name", SERVICE]);
        reply.lines().nth(1)?.trim().parse().ok()
    }

    fn config(&self) -> AppConfig {
        let mut document: serde_json::Value =
            serde_json::from_str(BASE_CONFIG_JSON).expect("base test config must parse");
        document["cache"]["host"] = serde_json::json!("127.0.0.1");
        document["cache"]["port"] = serde_json::json!(self.sentinel_ports[0]);
        document["cache"]["password"] = serde_json::json!(self.password);
        document["cache"]["sentinel"] = serde_json::json!({
            "service_name": SERVICE,
            "nodes": [
                { "host": "127.0.0.1", "port": self.sentinel_ports[1] },
                { "host": "127.0.0.1", "port": self.sentinel_ports[2] }
            ],
            "sentinel_password": self.sentinel_password,
        });
        serde_json::from_value(document).expect("test config must deserialize")
    }
}

/// Waits until Sentinel names a master other than `old`, then until the pool
/// writes to it, and returns the new master's port. The write is read back on
/// that port directly, so a pool still talking to the demoted node (where the
/// write would fail `READONLY`) cannot pass.
async fn pool_follows(topology: &Topology, pool: &RedisPool, old: u16, phase: &str) -> u16 {
    let started = Instant::now();
    let new_master = loop {
        match topology.master_port_per_sentinel() {
            Some(port) if port != old => break port,
            _ => {}
        }
        assert!(
            started.elapsed() < FAILOVER_DEADLINE,
            "{phase}: Sentinel never promoted a new master"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    };

    let key = format!("test:sentinel:{}", Uuid::now_v7());
    let value = Uuid::now_v7().to_string();
    loop {
        let write = tokio::time::timeout(
            Duration::from_secs(2),
            pool.set::<(), _, _>(&key, value.as_str(), Some(Expiration::EX(60)), None, false),
        )
        .await;
        if matches!(write, Ok(Ok(()))) && topology.server(new_master, &["get", &key]) == value {
            break;
        }
        assert!(
            started.elapsed() < FAILOVER_DEADLINE,
            "{phase}: the pool did not write to the new master {new_master} within \
             {FAILOVER_DEADLINE:?} (last attempt: {write:?})"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let limiter_key = format!("test:sentinel:rl:{}", Uuid::now_v7());
    let outcome = rate_limit::check(&attome_cache::Store::Redis(pool.clone()), &limiter_key, 10)
        .await
        .unwrap_or_else(|e| panic!("{phase}: rate_limit::check after the failover: {e:?}"));
    assert!(outcome.allowed, "{phase}: a fresh limiter key must admit");
    new_master
}

async fn subscriber_receives(
    pool: &RedisPool,
    messages: &mut tokio::sync::broadcast::Receiver<fred::types::Message>,
    channel: &str,
    phase: &str,
) {
    let marker = format!("{phase}-{}", Uuid::now_v7());
    let started = Instant::now();
    loop {
        assert!(
            started.elapsed() < FAILOVER_DEADLINE,
            "{phase}: the subscriber received nothing published after the failover"
        );
        let _: Result<i64, _> = pool.next().publish(channel, marker.as_str()).await;
        if let Ok(Ok(message)) =
            tokio::time::timeout(Duration::from_millis(500), messages.recv()).await
            && message.value.as_string().as_deref() == Some(marker.as_str())
        {
            return;
        }
    }
}

#[tokio::test]
#[ignore = "runs its own Redis + Sentinel container; see this file's header"]
async fn a_sentinel_pool_and_subscriber_follow_graceful_and_crash_failovers() {
    let topology = Topology::start();
    let config = topology.config();

    let pool = create_redis_pool(&config)
        .await
        .expect("create the pool through Sentinel");
    let subscriber = create_subscriber_client(&config)
        .await
        .expect("create the subscriber through Sentinel");
    let channel = format!("test:sentinel:{}", Uuid::now_v7());
    subscriber
        .subscribe(channel.clone())
        .await
        .expect("subscribe before any failover");
    let _manager = subscriber.manage_subscriptions();
    let mut messages = subscriber.message_rx();
    subscriber_receives(&pool, &mut messages, &channel, "before").await;

    // (a) Graceful: the old master stays up and is demoted to a replica, so a
    // pool that never re-resolves would keep a live socket to a read-only node.
    assert_eq!(
        topology.master_port_per_sentinel(),
        Some(topology.master_port)
    );
    let reply = topology.sentinel(&["sentinel", "failover", SERVICE]);
    assert_eq!(reply, "OK", "SENTINEL FAILOVER refused: {reply}");
    let promoted = pool_follows(&topology, &pool, topology.master_port, "graceful").await;
    assert_eq!(promoted, topology.replica_port);
    subscriber_receives(&pool, &mut messages, &channel, "graceful").await;

    // (b) Crash: the current master dies without a word.
    let _ = topology.server(promoted, &["shutdown", "nosave"]);
    let promoted_again = pool_follows(&topology, &pool, promoted, "crash").await;
    assert_eq!(promoted_again, topology.master_port);
    subscriber_receives(&pool, &mut messages, &channel, "crash").await;
}
