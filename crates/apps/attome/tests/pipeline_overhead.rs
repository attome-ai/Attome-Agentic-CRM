//! attome-server hardening Phase 2: what the assembled middleware pipeline costs
//! per request, and which Redis commands and SQL statements each layer issues.
//!
//! Not a correctness suite. The test is `#[ignore]` and runs explicitly, in
//! release, against the throwaway test database and the test Redis:
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test --release -p server --test pipeline_overhead -- --ignored --nocapture
//! ```
//!
//! Method:
//! - Router: `main.rs`'s `ServerBuilder` composition (liveness routes, core,
//!   public auth, protected auth, openapi and omnichannel bundles, the S2S
//!   layer) plus one no-op `GET` route as an extra bundle. The XRM system
//!   registers only `SecurityModel`; the other models add routes, not layers.
//! - Overhead: the no-op route through the full stack, minus the same handler
//!   on a bare `Router`, per credential kind and concurrency.
//! - Redis: a raw `MONITOR` connection, open only during counting windows. The
//!   test Redis is shared with other suites, so only commands carrying this
//!   run's identifiers are kept.
//! - SQL: sqlx's own `sqlx::query` event (one per statement), captured
//!   in-process only while a counting window is open.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::print_stdout,
    reason = "this measurement test prints its report for the reader"
)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tower::ServiceExt;
use tracing_subscriber::layer::{Context, SubscriberExt};
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const ALLOWED_ORIGIN: &str = "http://allowed.test";
const NOOP: &str = "/api/v1/__bench/noop";
const VERSION: &str = "/version";
const WARMUP: usize = 300;
const SEQUENTIAL: usize = 3000;
const CONCURRENCY: usize = 16;
const PER_TASK: usize = 250;
const COUNT_WINDOW: usize = 50;

// ── SQL capture ──────────────────────────────────────────────────────────────

static CAPTURE: AtomicBool = AtomicBool::new(false);
static STATEMENTS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Records sqlx's per-statement event while `CAPTURE` is set, prints every
/// `ERROR` event to stderr (the server logs the cause of a masked 500 at
/// `error`, and a benchmark that aborts on one must say why), and disables
/// everything else. `Interest::sometimes` keeps `enabled` evaluated per event,
/// so latency runs (capture off) skip sqlx's statement formatting.
struct SqlCapture;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SqlCapture {
    fn register_callsite(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if metadata.target() == "sqlx::query" {
            tracing::subscriber::Interest::sometimes()
        } else if *metadata.level() == tracing::Level::ERROR {
            tracing::subscriber::Interest::always()
        } else {
            tracing::subscriber::Interest::never()
        }
    }

    fn enabled(&self, metadata: &tracing::Metadata<'_>, _ctx: Context<'_, S>) -> bool {
        if metadata.target() == "sqlx::query" {
            CAPTURE.load(Ordering::Relaxed)
        } else {
            *metadata.level() == tracing::Level::ERROR
        }
    }

    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != "sqlx::query" {
            let mut fields = EventFields::default();
            event.record(&mut fields);
            eprintln!("server error [{}]: {}", event.metadata().target(), fields.0);
            return;
        }
        let mut visitor = SqlVisitor::default();
        event.record(&mut visitor);
        let sql = if visitor.statement.trim().is_empty() {
            visitor.summary
        } else {
            visitor.statement
        };
        STATEMENTS
            .lock()
            .unwrap()
            .push(sql.split_whitespace().collect::<Vec<_>>().join(" "));
    }
}

#[derive(Default)]
struct SqlVisitor {
    summary: String,
    statement: String,
}

impl tracing::field::Visit for SqlVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match field.name() {
            "summary" => self.summary = value.to_owned(),
            "db.statement" => self.statement = value.to_owned(),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let text = format!("{value:?}");
        let text = text.trim_matches('"').replace("\\n", " ");
        match field.name() {
            "summary" => self.summary = text,
            "db.statement" => self.statement = text,
            _ => {}
        }
    }
}

/// Every field of an event as `name=value`, for the stderr error trail.
#[derive(Default)]
struct EventFields(String);

impl tracing::field::Visit for EventFields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if !self.0.is_empty() {
            self.0.push_str(", ");
        }
        self.0.push_str(&format!("{}={value:?}", field.name()));
    }
}

fn install_sql_capture() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        tracing::subscriber::set_global_default(tracing_subscriber::registry().with(SqlCapture))
            .expect("install the SQL capture subscriber");
    });
}

fn sql_layer(sql: &str) -> &'static str {
    const MAP: &[(&str, &str)] = &[
        ("_sqlx_migrations", "handler (/version schema check)"),
        ("api_key", "authn: API key"),
        ("auth_epoch", "authn: session epoch"),
        ("ip_allow", "authz: IP allow-list"),
        ("privilege", "authz: security context"),
        ("role", "authz: security context"),
        ("mm_team", "authz: security context"),
        ("field_securi", "authz: security context"),
        (
            "select is_active from user_account",
            "authz: security context",
        ),
    ];
    let lower = sql.to_lowercase();
    MAP.iter()
        .find(|(needle, _)| lower.contains(needle))
        .map_or("unattributed", |(_, layer)| layer)
}

// ── Redis MONITOR ────────────────────────────────────────────────────────────

fn redis_addr() -> String {
    let host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into());
    let port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into());
    format!("{host}:{port}")
}

struct Monitor {
    lines: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Monitor {
    async fn start() -> Monitor {
        let stream = TcpStream::connect(redis_addr())
            .await
            .expect("connect to the test Redis for MONITOR");
        let (read, mut write) = stream.into_split();
        write.write_all(b"*1\r\n$7\r\nMONITOR\r\n").await.unwrap();
        let mut reader = BufReader::new(read);
        let mut first = String::new();
        reader.read_line(&mut first).await.unwrap();
        assert!(first.starts_with("+OK"), "MONITOR refused: {first}");

        let lines = Arc::new(Mutex::new(Vec::new()));
        let sink = lines.clone();
        let task = tokio::spawn(async move {
            let _keep_open = write;
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => sink.lock().unwrap().push(line.trim_end().to_owned()),
                }
            }
        });
        Monitor { lines, task }
    }

    async fn stop(self) -> Vec<String> {
        tokio::time::sleep(Duration::from_millis(300)).await;
        self.task.abort();
        std::mem::take(&mut *self.lines.lock().unwrap())
    }
}

/// `+<ts> [<db> <client>] "CMD" "arg"...` → (issued from inside a script, args).
fn parse_monitor_line(line: &str) -> Option<(bool, &str)> {
    let rest = line.strip_prefix('+')?;
    let open = rest.find('[')?;
    let close = rest.find(']')?;
    let from_script = rest[open + 1..close].contains("lua");
    Some((from_script, rest[close + 1..].trim()))
}

fn redis_layer(args: &str) -> &'static str {
    const MAP: &[(&str, &str)] = &[
        ("auth:denylist:", "authn: session revocation"),
        ("auth:epoch:", "authn: session epoch"),
        ("xrm:authz_epoch:", "authz: revocation epoch"),
        ("security:ctx:", "authz: security-context cache"),
        (
            "attome-server:touch:api_key",
            "authn: API key last-used touch",
        ),
        ("base:rl:preauth-ip:", "pre-auth rate limit"),
        ("attome-server:api-usage:", "rate limit: usage counter"),
        ("base:rl:", "rate limit"),
        ("base:idem:", "idempotency"),
        ("attome-db:rw-pin:", "read routing"),
    ];
    MAP.iter()
        .find(|(prefix, _)| args.contains(prefix))
        .map_or("unattributed", |(_, layer)| layer)
}

async fn redis_server_facts() -> String {
    let mut stream = TcpStream::connect(redis_addr()).await.unwrap();
    stream
        .write_all(b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n")
        .await
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut header = String::new();
    reader.read_line(&mut header).await.unwrap();
    let len: usize = header.trim().trim_start_matches('$').parse().unwrap_or(0);
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf)
        .lines()
        .filter(|l| {
            ["redis_version:", "dragonfly_version:", "os:", "arch_bits:"]
                .iter()
                .any(|p| l.starts_with(p))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

// ── App ──────────────────────────────────────────────────────────────────────

fn bench_config() -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 4,
                "max_body_size_bytes": 1048576, "request_timeout_secs": 30,
                "enable_session": true, "max_connection_num": 256,
                "max_connection_num_per_ip": 256, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-bench"
            }},
            "database": {{
                "host": "localhost", "port": 5555, "dbname": "unused_overridden_by_env",
                "user": "unused", "password": "unused", "schema": "attome_dev",
                "connection_number": 20, "timeout": 5.0
            }},
            "cache": {{
                "host": "{redis_host}", "port": {redis_port}, "password": "",
                "db": 0, "connection_pool_size": 16, "timeout": 2000,
                "l1_cache_size_mb": 8, "l1_cache_ttl_seconds": 60,
                "metadata_registry_enabled": false
            }},
            "storage": {{
                "s3_endpoint": "http://localhost:9000", "s3_public_endpoint": "",
                "s3_region": "us-east-1", "s3_access_key": "test", "s3_secret_key": "test",
                "s3_bucket": "attome-test", "s3_use_path_style": true, "s3_verify_ssl": false
            }},
            "auth": {{
                "jwt_secret": "{jwt_secret}", "jwt_issuer": "attome-test", "jwt_expiry_hours": 1,
                "oauth_google_client_id": "", "oauth_google_client_secret": ""
            }},
            "rate_limit": {{
                "anonymous_rpm": 1000000, "authenticated_rpm": 1000000, "pre_auth_rpm": 1000000
            }},
            "observability": {{
                "metrics_port": 0, "log_sampling_rate": 1.0, "trace_sampling_rate": 1.0,
                "enable_distributed_tracing": false
            }},
            "email": {{
                "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
                "smtp_password": "", "smtp_from_address": "test@test.local",
                "smtp_from_name": "test", "smtp_use_tls": false,
                "queue_poll_seconds": 30, "max_retries": 1, "batch_size": 1
            }},
            "google_ai": {{
                "api_key": "", "base_url": "https://example.invalid",
                "default_model": "none", "timeout_seconds": 1
            }},
            "llm_api": {{}},
            "external_api": {{}},
            "s2s": {{ "enabled": false }},
            "security": {{ "bootstrap_admin_email": null }},
            "cors": {{ "allowed_origins": ["{allowed_origin}"] }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
        allowed_origin = ALLOWED_ORIGIN,
    );
    serde_json::from_str(&json).expect("bench config JSON must deserialize into AppConfig")
}

async fn noop() -> &'static str {
    "ok"
}

async fn build_app() -> Option<(axum::Router, AppState, AppConfig)> {
    let mut config = bench_config();
    let db_url = attome_testkit::migrated_db_url()?;
    point_config_at(&mut config, &db_url);

    let db = attome_db::create_pool(&config)
        .await
        .expect("connect DATABASE_URL");
    let redis = attome_cache::create_redis_pool(&config)
        .await
        .expect("connect redis");
    let redis_coordination = attome_cache::create_role_redis_pool(
        &config,
        attome_cache::CacheRole::Coordination,
        &redis,
    )
    .await
    .expect("connect coordination redis");
    let storage = attome_storage::create_storage_client(&config)
        .await
        .expect("build storage client");
    let base = AppState::new(
        config.clone(),
        db.clone(),
        db.clone(),
        db,
        redis,
        redis_coordination,
        storage,
    );

    let system = EngineSystem::builder(attome_core::EngineState::new(base))
        .register(attome_security::model::SecurityModel)
        .build()
        .await
        .expect("build EngineSystem");
    system
        .state()
        .modules
        .store(Arc::new(attome_modules::ModuleSet::from_bits(
            [u64::MAX; 4],
        )));

    let attome_state = system.state().clone();
    let base_state = attome_state.base.clone();
    let bundle = attome_server::RouteBundle::new;
    let app = attome_server::ServerBuilder::new(base_state.clone(), config.clone())
        .with_liveness_routes(attome_server::liveness_routes().with_state(base_state.clone()))
        .add_bundle(system.core_routes())
        .add_bundle(bundle(
            attome::auth::public_routes(
                attome_state.modules.clone(),
                attome_audit::security::SecurityAuditor::from_state(&attome_state),
            )
            .with_state(base_state.clone()),
        ))
        .add_bundle(bundle(
            attome::auth::protected_routes(attome_audit::security::SecurityAuditor::from_state(
                &attome_state,
            ))
            .with_state(base_state.clone()),
        ))
        .add_bundle(bundle(
            attome::openapi::routes().with_state(base_state.clone()),
        ))
        .add_bundle(bundle(
            attome::omnichannel::routes().with_state(attome_state.clone()),
        ))
        .add_bundle(bundle(
            axum::Router::new().route(NOOP, axum::routing::get(noop)),
        ))
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));

    Some((app, base_state, config))
}

/// Returns (user id, token jti, cookie header value).
async fn seed_user_and_cookie(state: &AppState) -> (Uuid, Uuid, String) {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, is_active) VALUES ($1, $2, true)")
        .bind(user_id)
        .bind(format!("pipeline-bench-{user_id}"))
        .execute(&state.db)
        .await
        .expect("insert throwaway user_account");

    let now = chrono::Utc::now().timestamp();
    let jti = Uuid::now_v7();
    let claims = attome_auth::SessionClaims {
        sub: user_id,
        iat: now,
        exp: now + 3600,
        jti,
        epoch: 0,
        iss: state.config.auth.jwt_issuer.clone(),
        aud: state.config.jwt_audience().to_owned(),
        typ: attome_auth::TokenType::Session,
    };
    let ring = KeyRing::single(THROWAWAY_JWT_SECRET.to_string());
    let token = attome_auth::create_token(&claims, &ring).expect("encode throwaway jwt");
    (
        user_id,
        jti,
        format!("{}={token}", attome_auth::cookie::session_cookie_name(true)),
    )
}

/// Returns (key row id, public key, secret). Written straight to the throwaway
/// database with the deployment's own pepper, the same hash
/// `POST /api/v1/auth/api-keys` writes: the benchmark measures API-key
/// authentication, and minting over HTTP would need a stepped-up session
/// (D-510) that is beside the point here.
async fn mint_api_key(state: &AppState, user_id: Uuid) -> (String, String, String) {
    let public_key = format!("atk_pub_bench{}", Uuid::now_v7().simple());
    let secret = format!("atk_sec_bench{}", Uuid::now_v7().simple());
    let secret_hash = state.pepper_ring().hash(&secret);
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO api_key (user_ref, name, public_key, secret_hash)
         VALUES ($1, $2, $3, $4)
         RETURNING id",
    )
    .bind(user_id)
    .bind(format!("bench-{}", Uuid::now_v7()))
    .bind(&public_key)
    .bind(&secret_hash)
    .fetch_one(&state.db)
    .await
    .expect("insert throwaway api key");
    (id.to_string(), public_key, secret)
}

fn unique_peer() -> SocketAddr {
    let random = u128::from_be_bytes(*Uuid::now_v7().as_bytes()) & ((1u128 << 62) - 1);
    let ip = std::net::Ipv6Addr::from((0x2001_0db8_u128 << 96) | random);
    SocketAddr::from((ip, 40_000))
}

// ── Requests and timing ──────────────────────────────────────────────────────

#[derive(Clone)]
enum Auth {
    Cookie(String),
    ApiKey(String),
    Anonymous,
}

fn request(uri: &str, peer: SocketAddr, auth: &Auth) -> Request<Body> {
    let builder = Request::builder()
        .method("GET")
        .uri(uri)
        .extension(ConnectInfo(peer));
    let builder = match auth {
        Auth::Cookie(cookie) => builder.header("cookie", cookie),
        Auth::ApiKey(key) => builder.header("authorization", format!("ApiKey {key}")),
        Auth::Anonymous => builder,
    };
    builder.body(Body::empty()).unwrap()
}

async fn timed(app: axum::Router, req: Request<Body>) -> Duration {
    let start = Instant::now();
    let res = app.oneshot(req).await.unwrap();
    let status = res.status();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let elapsed = start.elapsed();
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    elapsed
}

async fn run_sequential(
    app: &axum::Router,
    uri: &str,
    peer: SocketAddr,
    auth: &Auth,
    n: usize,
) -> Vec<Duration> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(timed(app.clone(), request(uri, peer, auth)).await);
    }
    out
}

async fn run_concurrent(
    app: &axum::Router,
    uri: &'static str,
    peer: SocketAddr,
    auth: &Auth,
) -> Vec<Duration> {
    let tasks: Vec<_> = (0..CONCURRENCY)
        .map(|_| {
            let app = app.clone();
            let auth = auth.clone();
            tokio::spawn(async move { run_sequential(&app, uri, peer, &auth, PER_TASK).await })
        })
        .collect();
    let mut all = Vec::with_capacity(CONCURRENCY * PER_TASK);
    for task in tasks {
        all.extend(task.await.unwrap());
    }
    all
}

/// (p50, p95, p99, mean) in microseconds.
fn percentiles(mut samples: Vec<Duration>) -> [f64; 4] {
    samples.sort_unstable();
    let at = |q: f64| {
        let i = ((samples.len() as f64 * q) as usize).min(samples.len() - 1);
        samples[i].as_secs_f64() * 1e6
    };
    let mean = samples.iter().map(Duration::as_secs_f64).sum::<f64>() / samples.len() as f64 * 1e6;
    [at(0.50), at(0.95), at(0.99), mean]
}

// ── Counting windows ─────────────────────────────────────────────────────────

struct Window {
    requests: usize,
    redis: BTreeMap<(&'static str, String), usize>,
    redis_from_scripts: usize,
    sql: BTreeMap<(&'static str, String), usize>,
}

/// Sends `requests` identical requests with capture on. `tokens` maps this
/// run's identifiers to placeholders; a Redis command is kept only if it
/// carries one, or is the shared usage-counter hash for a benchmarked route.
async fn counting_window(
    app: &axum::Router,
    uri: &str,
    peer: SocketAddr,
    auth: &Auth,
    requests: usize,
    tokens: &[(String, &'static str)],
) -> Window {
    let monitor = Monitor::start().await;
    STATEMENTS.lock().unwrap().clear();
    CAPTURE.store(true, Ordering::Relaxed);
    for _ in 0..requests {
        timed(app.clone(), request(uri, peer, auth)).await;
    }
    CAPTURE.store(false, Ordering::Relaxed);
    let statements = std::mem::take(&mut *STATEMENTS.lock().unwrap());
    let lines = monitor.stop().await;

    let mut window = Window {
        requests,
        redis: BTreeMap::new(),
        redis_from_scripts: 0,
        sql: BTreeMap::new(),
    };
    for line in &lines {
        let Some((from_script, args)) = parse_monitor_line(line) else {
            continue;
        };
        let ours = tokens.iter().any(|(raw, _)| args.contains(raw.as_str()))
            || (args.contains("attome-server:api-usage:")
                && (args.contains(NOOP) || args.contains(VERSION)));
        if !ours {
            continue;
        }
        if from_script {
            window.redis_from_scripts += 1;
            continue;
        }
        let mut normalized = args.to_owned();
        for (raw, placeholder) in tokens {
            normalized = normalized.replace(raw.as_str(), placeholder);
        }
        // `VERB key`: for EVAL/EVALSHA the key follows the script and numkeys.
        let parts: Vec<&str> = normalized.trim_matches('"').split("\" \"").collect();
        let verb = parts[0].to_uppercase();
        let key_index = if verb.starts_with("EVAL") { 3 } else { 1 };
        let key: String = parts
            .get(key_index)
            .copied()
            .unwrap_or("")
            .chars()
            .take(70)
            .collect();
        let command = format!("{verb} {key}");
        *window
            .redis
            .entry((redis_layer(&normalized), command))
            .or_default() += 1;
    }
    for sql in statements {
        let shown: String = sql.chars().take(110).collect();
        *window.sql.entry((sql_layer(&sql), shown)).or_default() += 1;
    }
    window
}

fn print_window(title: &str, w: &Window) {
    let per = |count: usize| count as f64 / w.requests as f64;
    let redis_total: usize = w.redis.values().sum();
    let sql_total: usize = w.sql.values().sum();
    println!("\n### {title} ({} request(s))", w.requests);
    println!(
        "Redis commands per request: {:.2} (plus {:.2} issued inside scripts)",
        per(redis_total),
        per(w.redis_from_scripts)
    );
    for ((layer, command), count) in &w.redis {
        println!("  {:<32} {:>6.2}  {command}", layer, per(*count));
    }
    println!("SQL statements per request: {:.2}", per(sql_total));
    for ((layer, sql), count) in &w.sql {
        println!("  {:<32} {:>6.2}  {sql}", layer, per(*count));
    }
    let sec = |verb: &str| {
        w.redis
            .iter()
            .filter(|((_, c), _)| c.split(' ').next() == Some(verb) && c.contains("security:ctx:"))
            .map(|(_, n)| *n)
            .sum::<usize>()
    };
    let l2_reads = sec("GET");
    let writes = sec("SET") + sec("SETEX") + sec("PSETEX");
    if l2_reads + writes > 0 || w.redis.keys().any(|(l, _)| l.starts_with("authz")) {
        println!(
            "Security-context cache: L1 hits {}, L2 hits {}, misses {} (of {})",
            w.requests.saturating_sub(l2_reads),
            l2_reads.saturating_sub(writes),
            writes,
            w.requests
        );
    }
}

// ── The measurement ──────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "benchmark: run explicitly in release, see the module doc"]
async fn measure_middleware_overhead() {
    install_sql_capture();
    let (app, state, config) = skip_if_no_db!(build_app().await);

    let postgres: String = sqlx::query_scalar("SELECT version()")
        .fetch_one(&state.db)
        .await
        .unwrap();
    println!("## Environment");
    println!("build: release={}", !cfg!(debug_assertions));
    println!("postgres: {postgres}");
    println!("redis: {}", redis_server_facts().await);
    println!(
        "config: db pool {}, cache pool {}, cache timeout {}ms, metadata registry {}, rate limits raised to 1,000,000 rpm",
        config.database.connection_number,
        config.cache.connection_pool_size,
        config.cache.timeout,
        config.cache.metadata_registry_enabled
    );
    println!(
        "load: warmup {WARMUP}, sequential {SEQUENTIAL}, concurrent {CONCURRENCY}x{PER_TASK}, runtime 4 worker threads"
    );

    let (user_id, jti, cookie) = seed_user_and_cookie(&state).await;
    let (key_id, key_public, key_secret) = mint_api_key(&state, user_id).await;
    let peers = [unique_peer(), unique_peer(), unique_peer()];
    let scenarios = [
        (
            "cookie session",
            NOOP,
            peers[0],
            Auth::Cookie(cookie.clone()),
        ),
        (
            "API key",
            NOOP,
            peers[1],
            Auth::ApiKey(format!("{key_public}:{key_secret}")),
        ),
        (
            "anonymous (GET /version)",
            VERSION,
            peers[2],
            Auth::Anonymous,
        ),
    ];
    let mut tokens: Vec<(String, &'static str)> = vec![
        (user_id.to_string(), "{user}"),
        (jti.to_string(), "{jti}"),
        (key_id, "{key_id}"),
        (key_public, "{key_public}"),
    ];
    tokens.extend(peers.iter().map(|p| (p.ip().to_string(), "{ip}")));

    let bare = axum::Router::new().route(NOOP, axum::routing::get(noop));
    let bare_peer = unique_peer();
    run_sequential(&bare, NOOP, bare_peer, &Auth::Anonymous, WARMUP).await;
    let bare_seq =
        percentiles(run_sequential(&bare, NOOP, bare_peer, &Auth::Anonymous, SEQUENTIAL).await);
    let bare_conc = percentiles(run_concurrent(&bare, NOOP, bare_peer, &Auth::Anonymous).await);

    println!("\n## Latency (microseconds; overhead = full stack minus bare handler)");
    println!(
        "| scenario | concurrency | full p50 | full p95 | full p99 | full mean | bare p50 | bare p95 | bare p99 | overhead p50 | overhead p95 | overhead p99 |"
    );
    println!("|---|---|---|---|---|---|---|---|---|---|---|---|");
    let row = |name: &str, conc: usize, full: [f64; 4], bare: [f64; 4]| {
        println!(
            "| {name} | {conc} | {:.0} | {:.0} | {:.0} | {:.0} | {:.0} | {:.0} | {:.0} | {:.0} | {:.0} | {:.0} |",
            full[0],
            full[1],
            full[2],
            full[3],
            bare[0],
            bare[1],
            bare[2],
            full[0] - bare[0],
            full[1] - bare[1],
            full[2] - bare[2]
        );
    };
    for (name, uri, peer, auth) in &scenarios {
        run_sequential(&app, uri, *peer, auth, WARMUP).await;
        let seq = percentiles(run_sequential(&app, uri, *peer, auth, SEQUENTIAL).await);
        row(name, 1, seq, bare_seq);
        let conc = percentiles(run_concurrent(&app, uri, *peer, auth).await);
        row(name, CONCURRENCY, conc, bare_conc);
    }

    println!("\n## Per-layer Redis commands and SQL statements");
    for (name, uri, peer, auth) in &scenarios {
        let window = counting_window(&app, uri, *peer, auth, COUNT_WINDOW, &tokens).await;
        print_window(&format!("{name}, warm"), &window);
    }

    // Cold: a user, key and peer nothing has touched yet.
    let (cold_user, cold_jti, cold_cookie) = seed_user_and_cookie(&state).await;
    let cold_peer = unique_peer();
    let cold_tokens = vec![
        (cold_user.to_string(), "{user}"),
        (cold_jti.to_string(), "{jti}"),
        (cold_peer.ip().to_string(), "{ip}"),
    ];
    let window = counting_window(
        &app,
        NOOP,
        cold_peer,
        &Auth::Cookie(cold_cookie),
        1,
        &cold_tokens,
    )
    .await;
    print_window("cookie session, cold user", &window);

    // A cold key for a user nothing has touched yet: the key is written
    // straight to the database, so no request has warmed its owner's context.
    let (key_user, key_jti, _key_cookie) = seed_user_and_cookie(&state).await;
    let (cold_key_id, cold_public, cold_secret) = mint_api_key(&state, key_user).await;
    let key_peer = unique_peer();
    let key_tokens = vec![
        (key_user.to_string(), "{user}"),
        (key_jti.to_string(), "{jti}"),
        (cold_key_id, "{key_id}"),
        (cold_public.clone(), "{key_public}"),
        (key_peer.ip().to_string(), "{ip}"),
    ];
    let window = counting_window(
        &app,
        NOOP,
        key_peer,
        &Auth::ApiKey(format!("{cold_public}:{cold_secret}")),
        1,
        &key_tokens,
    )
    .await;
    print_window("API key, first use of a new key", &window);

    let anon_peer = unique_peer();
    let window = counting_window(
        &app,
        VERSION,
        anon_peer,
        &Auth::Anonymous,
        1,
        &[(anon_peer.ip().to_string(), "{ip}")],
    )
    .await;
    print_window("anonymous, new client address", &window);
}
