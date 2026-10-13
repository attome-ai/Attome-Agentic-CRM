//! Base-auth hardening plan item 1.3: a release-build benchmark of the Argon2
//! work behind `password::hash_password_async` / `verify_password_async`,
//! with exactly the parameters production uses.
//!
//! An example links the normally compiled `attome-auth`, so `password::hasher()`
//! is the production `Argon2::default()` here, never the `cfg(test)` minimum.
//! The benchmark proves that instead of assuming it: it hashes through the
//! public API, reads the parameters back out of that PHC string, asserts they
//! are m=19456 KiB, t=2, p=1, and times verifications of that same hash.
//! Verification re-derives its cost from the stored hash, so it is the same
//! work as hashing.
//!
//! ```powershell
//! cargo run --release -p attome-auth --example kdf_bench            # latency, sweep, executor
//! cargo run --release -p attome-auth --example kdf_bench -- executor   # executor phase only
//! cargo run --release -p attome-auth --example kdf_bench -- mem 4   # hold 4 concurrent ops
//! ```
//!
//! `mem <c>` holds `c` threads verifying continuously for 6 s, then idles 3 s
//! before exiting. Sample the process's peak working set from outside while it
//! runs. Every mode first hashes once through the executor, so even `mem 0`
//! and `mem 1` peak with one operation's memory already held (they measure the
//! same); the per-operation resident footprint is therefore
//! (peak(c) − peak(1)) ÷ (c − 1).

use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use argon2::password_hash::PasswordVerifier;
use argon2::{Algorithm, Argon2, Params, Version};
use attome_auth::password::{hash_password_async, verify_password_async};
use attome_types::AppError;

const PASSWORD: &str = "kdf-benchmark-password-not-a-secret";
const PRODUCTION_PARAMS: (u32, u32, u32) = (19_456, 2, 1);
const SWEEP_THREADS: [usize; 9] = [1, 2, 3, 4, 5, 6, 8, 12, 16];
const SWEEP_ROUNDS: usize = 2;
const SWEEP_SECS: u64 = 6;
const BURSTS: [usize; 6] = [4, 8, 16, 32, 64, 128];
const ARRIVAL_RATES: [u32; 7] = [20, 40, 60, 80, 120, 200, 300];
const ARRIVAL_SECS: u64 = 5;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build the tokio runtime");
    let stored = runtime
        .block_on(hash_password_async(
            attome_auth::NewPassword::platform_generated(PASSWORD),
        ))
        .expect("hash through the KDF executor");
    let params = production_params(&stored);

    if args.first().map(String::as_str) == Some("mem") {
        let threads = args.get(1).and_then(|v| v.parse().ok()).unwrap_or(0);
        hold_memory(&stored, &params, threads);
        return;
    }
    if args.first().map(String::as_str) == Some("executor") {
        executor_load(&runtime, &stored);
        return;
    }

    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
    println!("available_parallelism: {cpus}");
    println!(
        "stored hash parameters: m={} KiB, t={}, p={} ({})",
        params.m_cost(),
        params.t_cost(),
        params.p_cost(),
        stored.split('$').take(3).collect::<Vec<_>>().join("$")
    );
    latency(&stored, &params);
    sweep(&stored, &params);
    executor_load(&runtime, &stored);
}

/// The parameters of a hash the production executor wrote, asserted to be the
/// production defaults before anything is measured.
fn production_params(stored: &str) -> Params {
    assert!(
        stored.starts_with("$argon2id$v=19$"),
        "not an Argon2id v19 hash: {stored}"
    );
    let parsed = argon2::password_hash::phc::PasswordHash::new(stored)
        .expect("the executor's hash is a PHC string");
    let params = Params::try_from(&parsed).expect("Argon2 parameters in the hash");
    assert_eq!(
        (params.m_cost(), params.t_cost(), params.p_cost()),
        PRODUCTION_PARAMS,
        "the benchmark must run with the production parameters"
    );
    params
}

fn argon(params: &Params) -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone())
}

fn verify_once(argon: &Argon2<'_>, stored: &str) -> Duration {
    let started = Instant::now();
    argon
        .verify_password(PASSWORD.as_bytes(), stored)
        .expect("the benchmark password verifies");
    started.elapsed()
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    sorted[((sorted.len() - 1) as f64 * p).round() as usize]
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn latency(stored: &str, params: &Params) {
    let argon = argon(params);
    for _ in 0..3 {
        verify_once(&argon, stored);
    }
    let mut samples: Vec<Duration> = (0..30).map(|_| verify_once(&argon, stored)).collect();
    samples.sort();
    println!(
        "\nsingle verify, one thread, 30 samples: min {:.1} ms, p50 {:.1} ms, p95 {:.1} ms, max {:.1} ms",
        ms(samples[0]),
        ms(percentile(&samples, 0.5)),
        ms(percentile(&samples, 0.95)),
        ms(samples[samples.len() - 1])
    );
}

/// Raw Argon2 throughput with `threads` threads verifying flat out, bypassing
/// the executor, so the curve shows where more concurrency stops paying.
fn run_threads(
    stored: &str,
    params: &Params,
    threads: usize,
    duration: Duration,
) -> (f64, Duration, Duration) {
    let barrier = Arc::new(Barrier::new(threads));
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let stored = stored.to_owned();
            let params = params.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let argon = argon(&params);
                barrier.wait();
                let end = Instant::now() + duration;
                let mut latencies = Vec::new();
                while Instant::now() < end {
                    latencies.push(verify_once(&argon, &stored));
                }
                latencies
            })
        })
        .collect();
    let started = Instant::now();
    let mut all: Vec<Duration> = handles
        .into_iter()
        .flat_map(|h| h.join().expect("benchmark thread"))
        .collect();
    let wall = started.elapsed();
    all.sort();
    (
        all.len() as f64 / wall.as_secs_f64(),
        percentile(&all, 0.5),
        percentile(&all, 0.99),
    )
}

fn sweep(stored: &str, params: &Params) {
    println!("\nraw throughput sweep, {SWEEP_SECS} s per level, executor bypassed");
    println!("round  threads    ops/s  ops/s/thread   p50 ms   p99 ms");
    for round in 1..=SWEEP_ROUNDS {
        for threads in SWEEP_THREADS {
            let (ops, p50, p99) =
                run_threads(stored, params, threads, Duration::from_secs(SWEEP_SECS));
            println!(
                "{round:>5}  {threads:>7}  {ops:>7.1}  {:>12.1}  {:>7.1}  {:>7.1}",
                ops / threads as f64,
                ms(p50),
                ms(p99)
            );
        }
    }
}

struct LoadResult {
    served: usize,
    overloaded: usize,
    latencies: Vec<Duration>,
}

impl LoadResult {
    async fn collect(
        tasks: Vec<tokio::task::JoinHandle<(Duration, Result<bool, AppError>)>>,
    ) -> Self {
        let mut result = LoadResult {
            served: 0,
            overloaded: 0,
            latencies: Vec::with_capacity(tasks.len()),
        };
        for task in tasks {
            let (elapsed, outcome) = task.await.expect("load task");
            match outcome {
                Ok(true) => {
                    result.served += 1;
                    result.latencies.push(elapsed);
                }
                Ok(false) => panic!("the benchmark password failed to verify"),
                Err(AppError::Overloaded(_)) => result.overloaded += 1,
                Err(e) => panic!("unexpected executor error: {e:?}"),
            }
        }
        result.latencies.sort();
        result
    }
}

fn spawn_verify(stored: &str) -> tokio::task::JoinHandle<(Duration, Result<bool, AppError>)> {
    let stored = stored.to_owned();
    tokio::spawn(async move {
        let started = Instant::now();
        let outcome = verify_password_async(PASSWORD, &stored).await;
        (started.elapsed(), outcome)
    })
}

/// The production executor (its permits and acquire timeout exactly as
/// compiled), under a simultaneous burst and under steady open-loop arrivals.
fn executor_load(runtime: &tokio::runtime::Runtime, stored: &str) {
    println!("\nexecutor, production constants, burst fired at once");
    println!("burst  served  overloaded   wall ms   p50 ms   p99 ms   max ms");
    for burst in BURSTS {
        let started = Instant::now();
        let result = runtime.block_on(async {
            let tasks = (0..burst).map(|_| spawn_verify(stored)).collect();
            LoadResult::collect(tasks).await
        });
        let wall = started.elapsed();
        println!(
            "{burst:>5}  {:>6}  {:>10}  {:>8.0}  {:>7.1}  {:>7.1}  {:>7.1}",
            result.served,
            result.overloaded,
            ms(wall),
            ms(percentile(&result.latencies, 0.5)),
            ms(percentile(&result.latencies, 0.99)),
            ms(result.latencies.last().copied().unwrap_or_default())
        );
        std::thread::sleep(Duration::from_millis(500));
    }

    println!("\nexecutor, production constants, open-loop arrivals for {ARRIVAL_SECS} s");
    println!("rate/s  offered  served  overloaded  served/s   p50 ms   p99 ms");
    for rate in ARRIVAL_RATES {
        let offered = (rate as u64 * ARRIVAL_SECS) as usize;
        let started = Instant::now();
        let result = runtime.block_on(async {
            let mut ticker = tokio::time::interval(Duration::from_secs_f64(1.0 / rate as f64));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
            let mut tasks = Vec::with_capacity(offered);
            for _ in 0..offered {
                ticker.tick().await;
                tasks.push(spawn_verify(stored));
            }
            LoadResult::collect(tasks).await
        });
        let wall = started.elapsed();
        println!(
            "{rate:>6}  {offered:>7}  {:>6}  {:>10}  {:>8.1}  {:>7.1}  {:>7.1}",
            result.served,
            result.overloaded,
            result.served as f64 / wall.as_secs_f64(),
            ms(percentile(&result.latencies, 0.5)),
            ms(percentile(&result.latencies, 0.99))
        );
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn hold_memory(stored: &str, params: &Params, threads: usize) {
    println!(
        "pid {} holding {threads} concurrent verifications",
        std::process::id()
    );
    if threads == 0 {
        std::thread::sleep(Duration::from_secs(6));
    } else {
        run_threads(stored, params, threads, Duration::from_secs(6));
    }
    println!("done");
    std::thread::sleep(Duration::from_secs(3));
}
