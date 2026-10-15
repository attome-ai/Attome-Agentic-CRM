//! Two processes booting against the same fresh database must both finish,
//! and the platform seeding must run once, not once per process.
//!
//! `server` and `worker` both call `attome::boot::init`, and that function
//! applies every platform bundle (`apply_platform_bundle`, D-478). Nothing
//! serialized that across processes. Staging-smoke run 34845417412 showed the
//! result on a split deployment: each process planned the same bundles, the
//! other's writes invalidated the plan's basis (`Conflict("basis changed since
//! plan")`), the error propagated out of `init` and the process exited. The
//! server restarted 5 times and the worker 8 times, and the worker's
//! concurrent provisioning of `user_account_mm_team` hit the migrator
//! role's 500ms `statement_timeout` on `CREATE INDEX CONCURRENTLY`.
//!
//! **Why child processes, not two `init` calls in this one.**
//! `attome_core::seed_gate` keeps its watermark snapshot in a process-wide
//! static. Two in-process calls would share it, so one call would see the
//! other's stamps without reading the database — something two containers
//! never do. This test re-runs its own binary twice (the ignored
//! `concurrent_boot_child_process` test below) so each boot has its own
//! process state, exactly like `server` and `worker`.
//!
//! **Genuinely concurrent.** Both children wait for the same wall-clock
//! instant before calling `init`, report when they actually started, and the
//! test fails if those starts are not close together.
//!
//! **What "serialized" means here.** Both children exit 0, every plan row the
//! seeding wrote succeeded, and no platform bundle was planned twice: a boot
//! that waits for the other must find its watermarks and skip, not provision
//! the same objects again.
//!
//! Migrations run in this process first, the way the `migrate` one-shot runs
//! before `server`/`worker` in a split deployment, so the children boot with
//! `database.migrate_on_boot = false` and race only on seeding.
//!
//! Same requirements and isolation as `fresh_bootstrap.rs`: a Postgres role
//! with `CREATEDB` in `DATABASE_URL`, Redis at `TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`, and `APP_ENV=debug`. The children get `APP_ENV=debug`
//! and no `DATABASE_URL`, so every pool they open is built from the throwaway
//! database's own URL.
//!
//! ```powershell
//! $env:APP_ENV = "debug"
//! $env:TEST_REDIS_PORT = "6380"
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/attomedb_test"
//! cargo test -p server --test concurrent_boot
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use attome_config::AppConfig;
use attome_testkit::DbUrlParts;
use attome_testkit::skip_if_no_db;
use sqlx::PgPool;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Same schema `fresh_bootstrap.rs` uses: the one a real deployment creates.
const DEPLOYMENT_SCHEMA: &str = "attome_dev";

const CHILD_TEST_NAME: &str = "concurrent_boot_child_process";
const CHILD_DB_URL_ENV: &str = "CONCURRENT_BOOT_CHILD_DB_URL";
const CHILD_START_AT_ENV: &str = "CONCURRENT_BOOT_CHILD_START_AT_MS";

/// Lead time before both children call `init`: enough for two copies of this
/// binary to start and build their config, so neither arrives late.
const CHILD_START_DELAY: Duration = Duration::from_secs(5);

/// How far apart the two `init` calls may start and still count as
/// concurrent. Seeding begins well after `init` starts (pools, identity
/// checks, license load come first), so starts this close put both processes
/// in the seeding section at the same time.
const MAX_START_SKEW_MS: u64 = 1_000;

/// A fresh database's full seeding took about 18 s in staging; a boot that
/// waits for another one needs roughly twice that. Generous, but bounded so a
/// hung child fails the test instead of hanging the whole run.
const CHILD_TIMEOUT: Duration = Duration::from_secs(600);

/// `fresh_bootstrap.rs`'s config, with `migrate_on_boot = false`: this test
/// migrates once up front, the way a split deployment's `migrate` job does.
fn test_config(db: &DbUrlParts) -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 1048576, "request_timeout_secs": 5,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            }},
            "database": {{
                "host": "{host}", "port": {port}, "dbname": "{dbname}",
                "user": "{user}", "password": "{password}", "schema": "{schema}",
                "connection_number": 5, "timeout": 5.0, "migrate_on_boot": false,
                "runtime": {{ "user": "attome_runtime", "password": "boot-test-runtime-pw" }},
                "migrator": {{ "user": "attome_migrator", "password": "boot-test-migrator-pw" }},
                "readonly": {{ "user": "attome_readonly", "password": "boot-test-readonly-pw" }}
            }},
            "cache": {{
                "host": "{redis_host}", "port": {redis_port}, "password": "",
                "db": 0, "connection_pool_size": 4, "timeout": 2000,
                "l1_cache_size_mb": 8, "l1_cache_ttl_seconds": 60,
                "metadata_registry_enabled": true
            }},
            "storage": {{
                "s3_endpoint": "http://localhost:9000", "s3_public_endpoint": "",
                "s3_region": "us-east-1", "s3_access_key": "test", "s3_secret_key": "test",
                "s3_bucket": "attome-test", "s3_use_path_style": true, "s3_verify_ssl": false
            }},
            "auth": {{
                "jwt_secret": "test-only-throwaway-secret-do-not-use-in-prod",
                "jwt_issuer": "attome-test", "jwt_expiry_hours": 1,
                "oauth_google_client_id": "", "oauth_google_client_secret": ""
            }},
            "rate_limit": {{
                "anonymous_rpm": 1000, "authenticated_rpm": 1000, "per_endpoint_limits": {{}}
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
            "cors": {{ "allowed_origins": ["http://allowed.test"] }}
        }}"#,
        host = db.host,
        port = db.port,
        dbname = db.dbname,
        user = db.user,
        password = db.password,
        schema = DEPLOYMENT_SCHEMA,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
    );
    serde_json::from_str(&json).expect("test config JSON must deserialize into AppConfig")
}

fn unix_ms() -> u64 {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch");
    u64::try_from(since_epoch.as_millis()).expect("milliseconds since epoch fit in u64")
}

/// Refuses to write anywhere but the throwaway database (same guard as
/// `fresh_bootstrap.rs`).
async fn assert_connected_to(pool: &PgPool, expected_dbname: &str) {
    let (current,): (String,) = sqlx::query_as("SELECT current_database()")
        .fetch_one(pool)
        .await
        .expect("SELECT current_database() must succeed on a connected pool");
    assert_eq!(
        current, expected_dbname,
        "this test must only ever write to its own throwaway database — refusing to \
         migrate '{current}'"
    );
}

/// The number after `marker=` on the first line of `stdout` that carries it.
/// Not anchored to the start of the line: libtest prints a test's first
/// `println!` on the same line as `test <name> ... `.
fn reported_ms(stdout: &str, marker: &str) -> Option<u64> {
    let prefix = format!("{marker}=");
    stdout.lines().find_map(|line| {
        let (_, rest) = line.split_once(prefix.as_str())?;
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        digits.parse().ok()
    })
}

fn tail(text: &str, lines: usize) -> String {
    let all: Vec<&str> = text.lines().collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

struct ChildRun {
    label: &'static str,
    output: std::process::Output,
}

impl ChildRun {
    fn stdout(&self) -> String {
        String::from_utf8_lossy(&self.output.stdout).into_owned()
    }

    fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.output.stderr).into_owned()
    }

    fn describe(&self) -> String {
        format!(
            "child {} exited with {}\n--- stdout (tail) ---\n{}\n--- stderr (tail) ---\n{}",
            self.label,
            self.output.status,
            tail(&self.stdout(), 40),
            tail(&self.stderr(), 60)
        )
    }
}

async fn run_child(label: &'static str, db_url: &str, start_at_ms: u64) -> ChildRun {
    let exe = std::env::current_exe().expect("locate this test binary to re-run it");
    let child = tokio::process::Command::new(exe)
        .args([
            "--exact",
            CHILD_TEST_NAME,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_DB_URL_ENV, db_url)
        .env(CHILD_START_AT_ENV, start_at_ms.to_string())
        .env("APP_ENV", "debug")
        .env_remove("DATABASE_URL")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap_or_else(|e| panic!("spawn child {label}: {e}"));
    let output = tokio::time::timeout(CHILD_TIMEOUT, child.wait_with_output())
        .await
        .unwrap_or_else(|_| panic!("child {label} did not finish booting within {CHILD_TIMEOUT:?}"))
        .unwrap_or_else(|e| panic!("wait for child {label}: {e}"));
    ChildRun { label, output }
}

#[tokio::test]
async fn concurrent_boots_seed_the_platform_once_and_both_succeed() {
    let fresh_db = skip_if_no_db!(attome_testkit::empty_database("concurrent_boot").await);
    let db_parts = DbUrlParts::parse(fresh_db.url()).expect("DATABASE_URL must parse");
    assert_eq!(
        db_parts.dbname,
        fresh_db.name(),
        "the config below must be built from the throwaway database's own URL"
    );
    let config = test_config(&db_parts);

    // The `migrate` job's sequence, once, before either process starts.
    let migration_db = attome_db::create_direct_pool(&config)
        .await
        .expect("create_direct_pool must connect to the fresh database");
    assert_connected_to(&migration_db, fresh_db.name()).await;
    attome_db::ensure_schema(&migration_db, &config)
        .await
        .expect("ensure_schema must create the deployment schema");
    attome_db::run_migrations(&migration_db, &MIGRATOR)
        .await
        .expect("run_migrations must apply every compiled migration");
    attome::role_seed_lock::seed_roles_and_pepper_registry(&migration_db, &config)
        .await
        .expect("role seed and pepper registry must succeed after migrations");

    let stamps_before: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM {DEPLOYMENT_SCHEMA}.seed_watermark"
    ))
    .fetch_one(&migration_db)
    .await
    .expect("count seed watermarks before boot");
    assert_eq!(
        stamps_before, 0,
        "both boots must start from unseeded metadata, or they have nothing to race on"
    );

    let start_at_ms =
        unix_ms() + u64::try_from(CHILD_START_DELAY.as_millis()).expect("start delay fits in u64");
    let (a, b) = tokio::join!(
        run_child("a", fresh_db.url(), start_at_ms),
        run_child("b", fresh_db.url(), start_at_ms),
    );

    // Full child output, kept for diagnosis: the assertion messages below
    // only carry a tail.
    let log_dir = std::env::temp_dir().join(format!("concurrent_boot_{}", fresh_db.name()));
    std::fs::create_dir_all(&log_dir).expect("create the child log directory");
    for child in [&a, &b] {
        let path = log_dir.join(format!("child_{}.log", child.label));
        std::fs::write(
            &path,
            format!(
                "exit: {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
                child.output.status,
                child.stdout(),
                child.stderr()
            ),
        )
        .expect("write the child log");
        println!("child {} output: {}", child.label, path.display());
    }

    // Both boots must succeed on their first attempt. A deployment would
    // restart the loser and eventually converge; that restart loop is the
    // defect, so the test does not allow it. Both children are described on
    // failure: the one that succeeded shows what the other was racing.
    let both_succeeded = [&a, &b]
        .iter()
        .all(|child| child.output.status.success() && child.stdout().contains("CHILD_BOOT_OK"));
    assert!(
        both_succeeded,
        "both concurrent boots must succeed.\n{}\n\n{}",
        a.describe(),
        b.describe()
    );

    // Genuinely concurrent, not one after the other.
    let started = |child: &ChildRun| {
        reported_ms(&child.stdout(), "CHILD_INIT_STARTED_AT_MS").unwrap_or_else(|| {
            panic!(
                "child {} did not report its start\n{}",
                child.label,
                child.describe()
            )
        })
    };
    let finished = |child: &ChildRun| {
        reported_ms(&child.stdout(), "CHILD_INIT_FINISHED_AT_MS").unwrap_or_else(|| {
            panic!(
                "child {} did not report its finish\n{}",
                child.label,
                child.describe()
            )
        })
    };
    let (a_start, b_start) = (started(&a), started(&b));
    let (a_end, b_end) = (finished(&a), finished(&b));
    println!(
        "child a: init {a_start}..{a_end} ({} ms); child b: init {b_start}..{b_end} ({} ms)",
        a_end - a_start,
        b_end - b_start
    );
    let skew = a_start.abs_diff(b_start);
    assert!(
        skew <= MAX_START_SKEW_MS,
        "the two boots started {skew} ms apart (limit {MAX_START_SKEW_MS} ms), so this run \
         did not exercise concurrent seeding; raise CHILD_START_DELAY rather than relax this"
    );

    // Seeding actually ran, and every changeset it applied finished. Platform
    // seeding goes through the changeset ledger: one row per changeset and
    // phase, so a second boot that planned the same changeset again would hit
    // the (changeset_id, phase) key rather than add a row.
    let ledger = format!("{DEPLOYMENT_SCHEMA}.changeset_apply");
    let succeeded: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM {ledger} WHERE status IN ('succeeded', 'adopted')"
    ))
    .fetch_one(&migration_db)
    .await
    .expect("count applied changesets");
    assert!(
        succeeded > 0,
        "no platform changeset was applied, so seeding never ran and this test proved nothing"
    );
    let unfinished: Vec<(String, String, Option<String>)> = sqlx::query_as(&format!(
        "SELECT ref, status, error_message FROM {ledger} WHERE status NOT IN ('succeeded', 'adopted') ORDER BY created_at"
    ))
    .fetch_all(&migration_db)
    .await
    .expect("read unfinished changesets");
    assert!(
        unfinished.is_empty(),
        "every platform changeset applied during the concurrent boots must finish; not finished (ref, status, error): {unfinished:?}"
    );

    // Each changeset phase applied once: the boot that ran second found the
    // first boot's ledger rows and skipped, instead of applying the same
    // changeset again.
    let applied_twice: Vec<(String, i64)> = sqlx::query_as(&format!(
        "SELECT ref, COUNT(*) FROM {ledger} GROUP BY changeset_id, phase, ref HAVING COUNT(*) > 1 ORDER BY ref"
    ))
    .fetch_all(&migration_db)
    .await
    .expect("read changesets applied more than once");
    assert!(
        applied_twice.is_empty(),
        "each platform changeset must be applied once across both boots; applied more than once (ref, rows): {applied_twice:?}"
    );

    let stamps_after: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM {DEPLOYMENT_SCHEMA}.seed_watermark"
    ))
    .fetch_one(&migration_db)
    .await
    .expect("count seed watermarks after boot");
    assert!(
        stamps_after > 0,
        "seeding must leave watermarks behind for later boots to skip on"
    );

    migration_db.close().await;
}

/// Stack for the child's boot thread — the same size `main.rs` gives the
/// thread that runs `attome::boot::init`. The boot future is too large for a
/// default thread stack in a debug build (`main.rs`'s own comment); a libtest
/// thread overflowed it here with `STATUS_STACK_OVERFLOW`.
const BOOT_THREAD_STACK_BYTES: usize = 64 * 1024 * 1024;

/// One boot, run in its own process by the test above. Returns immediately
/// when that test did not start it, so a plain `cargo test -- --ignored`
/// passes it without touching any database.
///
/// Starts `init` the way `main.rs` does: a dedicated thread with a 64 MiB
/// stack and a multi-thread tokio runtime.
#[test]
#[ignore = "child process of concurrent_boots_seed_the_platform_once_and_both_succeed"]
fn concurrent_boot_child_process() {
    let Ok(db_url) = std::env::var(CHILD_DB_URL_ENV) else {
        return;
    };
    let start_at_ms: u64 = std::env::var(CHILD_START_AT_ENV)
        .expect("the parent test sets the start instant")
        .parse()
        .expect("the start instant is a millisecond timestamp");
    let config = test_config(&DbUrlParts::parse(&db_url).expect("DATABASE_URL must parse"));
    // `AppError::Internal` masks its cause in `Display`; the cause is only
    // logged. WARN everywhere keeps the error lines without the per-attribute
    // INFO noise; INFO for the seed lock and bundle apply records, with
    // timestamps, which process waited and which one applied each bundle.
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "warn,attome::platform_seed_lock=info,attome_api::bundle::apply=info",
        ))
        .try_init();

    let outcome = std::thread::Builder::new()
        .stack_size(BOOT_THREAD_STACK_BYTES)
        .spawn(move || {
            let now = unix_ms();
            if start_at_ms > now {
                #[expect(
                    clippy::disallowed_methods,
                    reason = "a plain thread, before its runtime exists"
                )]
                std::thread::sleep(Duration::from_millis(start_at_ms - now));
            }
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("build the child's tokio runtime")
                .block_on(async {
                    println!("CHILD_INIT_STARTED_AT_MS={}", unix_ms());
                    let result = attome::boot::init(&config).await;
                    println!("CHILD_INIT_FINISHED_AT_MS={}", unix_ms());
                    // `Box<dyn Error>` is not `Send`; carry the message out.
                    result.map(drop).map_err(|e| e.to_string())
                })
        })
        .expect("spawn the child's boot thread")
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));

    match outcome {
        Ok(()) => println!("CHILD_BOOT_OK"),
        Err(e) => panic!("CHILD_BOOT_ERROR: {e}"),
    }
}
