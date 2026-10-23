//! AA14-T4: allocation budgets for the key requests `request_counts` counts
//! calls for (get a record, list 50 records, update a record, global search,
//! sign in), on the same fixture and measured warm the same way.
//!
//! This binary's global allocator counts the bytes allocated, and the peak
//! live bytes, while the measured request's own task is being polled: a flag
//! set around each poll of that future, read by the allocator on the polling
//! thread. Work the request hands to another task (a blocking password hash,
//! a spawned write) and the runtime's background tasks are not counted.
//!
//! The baselines are `request_allocs.json`. A value more than 20% above its
//! baseline fails; one more than 20% below it is printed, so the change that
//! lowered it also lowers the baseline.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod key_requests;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::task::{Context, Poll};

use axum::http::{Method, StatusCode};
use key_requests::{App, PASSWORD, fixture, if_match, seed_password_user, start};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

/// How far above its baseline a value may go.
const TOLERANCE: f64 = 0.20;

thread_local! {
    /// Whether this thread is polling the measured request now.
    static MEASURING: Cell<bool> = const { Cell::new(false) };
}

/// Only one request is measured at a time.
static ACTIVE: AtomicBool = AtomicBool::new(false);
static ALLOCATED: AtomicU64 = AtomicU64::new(0);
static LIVE: AtomicI64 = AtomicI64::new(0);
static PEAK: AtomicI64 = AtomicI64::new(0);

struct Counting;

fn measuring() -> bool {
    ACTIVE.load(Ordering::Relaxed) && MEASURING.try_with(Cell::get).unwrap_or(false)
}

fn record_alloc(size: usize) {
    ALLOCATED.fetch_add(size as u64, Ordering::Relaxed);
    let live = LIVE.fetch_add(size as i64, Ordering::Relaxed) + size as i64;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

// SAFETY: every method forwards to `System` with the caller's arguments and
// returns its result unchanged; the counting touches only atomics and a
// `const`-initialised thread local, neither of which allocates.
#[allow(
    unsafe_code,
    reason = "a counting allocator must implement the unsafe GlobalAlloc trait"
)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if measuring() {
            record_alloc(layout.size());
        }
        // SAFETY: the caller's contract for `alloc` is passed on as is.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if measuring() {
            LIVE.fetch_sub(layout.size() as i64, Ordering::Relaxed);
        }
        // SAFETY: as for `alloc`.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if measuring() {
            record_alloc(layout.size());
        }
        // SAFETY: as for `alloc`.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if measuring() {
            if new_size > layout.size() {
                record_alloc(new_size - layout.size());
            } else {
                LIVE.fetch_sub((layout.size() - new_size) as i64, Ordering::Relaxed);
            }
        }
        // SAFETY: as for `alloc`.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// A future whose polls are counted.
struct Measured<F>(Pin<Box<F>>);

impl<F: Future> Future for Measured<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        MEASURING.with(|m| m.set(true));
        let out = self.0.as_mut().poll(cx);
        MEASURING.with(|m| m.set(false));
        out
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
struct Allocs {
    /// Bytes allocated over the request.
    bytes: u64,
    /// The most bytes the request held at once.
    peak: u64,
}

async fn counted<F: Future>(future: F) -> (F::Output, Allocs) {
    ALLOCATED.store(0, Ordering::Relaxed);
    LIVE.store(0, Ordering::Relaxed);
    PEAK.store(0, Ordering::Relaxed);
    ACTIVE.store(true, Ordering::Relaxed);
    let out = Measured(Box::pin(future)).await;
    ACTIVE.store(false, Ordering::Relaxed);
    let allocs = Allocs {
        bytes: ALLOCATED.load(Ordering::Relaxed),
        peak: PEAK.load(Ordering::Relaxed).max(0) as u64,
    };
    (out, allocs)
}

fn baselines() -> BTreeMap<String, Allocs> {
    serde_json::from_str(include_str!("request_allocs.json"))
        .expect("request_allocs.json is a map of request name to {bytes, peak}")
}

async fn measure(
    app: &App,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> Allocs {
    let ((status, response), allocs) = counted(app.send(method, path, headers, body)).await;
    assert!(status.is_success(), "{path}: {status} {response}");
    allocs
}

async fn update(app: &App, entity: &str, id: Uuid, counted: bool) -> Allocs {
    let version = if_match(app, entity, id).await;
    let path = format!("/api/v1/{entity}/{id}");
    let headers = [("if-match", version.as_str())];
    let body = Some(json!({ "title": format!("updated {id}") }));
    if counted {
        measure(app, Method::PATCH, &path, &headers, body).await
    } else {
        let (status, response) = app.send(Method::PATCH, &path, &headers, body).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        Allocs::default()
    }
}

/// Whether `value` is within the tolerance above `baseline`.
fn within(value: u64, baseline: u64) -> bool {
    (value as f64) <= (baseline as f64) * (1.0 + TOLERANCE)
}

#[test]
fn allocs_within_tolerance_checks_both_sides() {
    assert!(within(120, 100));
    assert!(!within(121, 100));
    assert!(within(50, 100));
}

// feature: AA14
#[test]
fn key_requests_within_their_allocation_budgets() {
    attome_testkit::run_shared(async {
        let Some(app) = start().await else {
            return;
        };
        let (child, ids) = fixture(&app).await;
        let email = seed_password_user(&app).await;
        let login = |email: &str| json!({ "email": email, "password": PASSWORD });
        let list = |page_size: i64| json!({ "entity": child, "page_size": page_size });
        let record = |id: Uuid| format!("/api/v1/{child}/{id}");

        let mut measured: BTreeMap<&str, Allocs> = BTreeMap::new();

        app.send(Method::GET, &record(ids[1]), &[], None).await;
        measured.insert(
            "record_get",
            measure(&app, Method::GET, &record(ids[0]), &[], None).await,
        );

        app.send(Method::POST, "/api/v1/query/execute", &[], Some(list(10)))
            .await;
        measured.insert(
            "record_list_50",
            measure(
                &app,
                Method::POST,
                "/api/v1/query/execute",
                &[],
                Some(list(50)),
            )
            .await,
        );

        update(&app, &child, ids[2], false).await;
        measured.insert("record_update", update(&app, &child, ids[3], true).await);

        app.send(Method::GET, "/api/v1/search?q=warm", &[], None)
            .await;
        measured.insert(
            "global_search",
            measure(&app, Method::GET, "/api/v1/search?q=counted", &[], None).await,
        );

        app.send(Method::POST, "/api/v1/auth/login", &[], Some(login(&email)))
            .await;
        measured.insert(
            "sign_in",
            measure(
                &app,
                Method::POST,
                "/api/v1/auth/login",
                &[],
                Some(login(&email)),
            )
            .await,
        );

        let baselines = baselines();
        let mut over = Vec::new();
        for (name, allocs) in &measured {
            let base = baselines
                .get(*name)
                .unwrap_or_else(|| panic!("request_allocs.json has no baseline for {name}"));
            println!(
                "{name}: {} bytes allocated (baseline {}), peak {} bytes (baseline {})",
                allocs.bytes, base.bytes, allocs.peak, base.peak
            );
            if !within(allocs.bytes, base.bytes) || !within(allocs.peak, base.peak) {
                over.push(*name);
            } else if (allocs.bytes as f64) < (base.bytes as f64) * (1.0 - TOLERANCE)
                || (allocs.peak as f64) < (base.peak as f64) * (1.0 - TOLERANCE)
            {
                println!(
                    "{name} now allocates much less: lower its baseline in request_allocs.json \
                     to {{ \"bytes\": {}, \"peak\": {} }} in this change",
                    allocs.bytes, allocs.peak
                );
            }
        }
        assert!(
            over.is_empty(),
            "more than 20% above their allocation baselines: {over:?} (values above; raise a \
             baseline only on purpose)"
        );
    });
}
