//! C10-D — the conversational loop under representative concurrency.
//!
//! Ignored by default: it is a measurement, not a regression test, and it
//! holds the database for tens of seconds. Run it explicitly against a
//! throwaway database:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://…/attomedb_tmpl_c4?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-ai --test turn_load -- --ignored --nocapture
//! ```
//!
//! The model is a stand-in with a **fixed per-step latency**
//! (`TURN_LOAD_MODEL_MS`, default 100), so the numbers measure the platform,
//! not a provider. Two phases, each at twice the pool size in concurrent turns
//! (`connection_number` is 8 in the test config, so 16; `TURN_LOAD_CONCURRENCY`
//! overrides it):
//!
//! 1. **Six-step turns** — five `record.get` dispatches, then a streamed
//!    answer: `MAX_TOOL_STEPS`, the loop's worst case. Measures the platform's
//!    overhead per model step: the turn's wall time less the model's fixed
//!    latency, over its six model calls.
//! 2. **One-step turns** — a streamed answer at once. Measures the time from
//!    the turn's start to its first delta at a subscriber, less the model's
//!    first-byte latency.
//!
//! Then, over every conversation both phases touched: every turn completed
//! (a pool-acquire timeout fails the turn, so this is the "zero timeouts"
//! target), and every event log is gapless with no duplicate ordinal.
//!
//! The targets are the plan's (`05` § C10, fixed before the first run):
//! overhead per step p95 ≤ 50 ms; first delta p95 ≤ 300 ms plus the model's
//! first byte; zero failed turns; zero gaps. The report is printed as one JSON
//! line and recorded in `document/chatbot/07-acceptance-matrix.md`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use attome_ai::conversation::{self, NewConversation, Surface, TerminalState};
use attome_ai::execute::Executors;
use attome_ai::registry::ActionRegistry;
use attome_ai::session::AgentSession;
use attome_ai::turn::{self, TurnInputs};
use attome_core::EngineState;
use axum::response::IntoResponse;
use axum::{Json, Router, routing::post};
use serde_json::{Value, json};
use uuid::Uuid;

const TOOL_STEPS: usize = 5;
const OVERHEAD_P95_MS: f64 = 50.0;
const FIRST_DELTA_P95_MS: f64 = 300.0;

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

// ---------------------------------------------------------------------------
// The stand-in model: stateless, fixed latency
// ---------------------------------------------------------------------------

/// Asks for `record.get` until the request carries `tool_steps` tool results
/// after its last user message, then answers — so one server drives any
/// number of concurrent turns without a per-conversation script.
async fn spawn_model(latency: Duration, tool_steps: usize) -> String {
    let app = Router::new().route(
        attome_inference::CHAT_COMPLETIONS_PATH,
        post(move |Json(body): Json<Value>| async move {
            tokio::time::sleep(latency).await;
            let messages = body["messages"].as_array().cloned().unwrap_or_default();
            let since_user = messages
                .iter()
                .rev()
                .take_while(|m| m["role"] != "user")
                .filter(|m| m["role"] == "tool")
                .count();
            let frames = if since_user < tool_steps {
                let args = json!({
                    "entity": "user_account",
                    // No such record: the read still runs authorization,
                    // metadata resolution and the query, which is the load.
                    "record_id": Uuid::nil().to_string(),
                });
                vec![
                    json!({"choices": [{"index": 0, "delta": {"tool_calls": [{
                        "index": 0, "id": format!("load-{}", Uuid::now_v7().simple()),
                        "type": "function",
                        "function": {"name": "record.get", "arguments": args.to_string()}
                    }]}}]}),
                    json!({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}),
                ]
            } else {
                vec![
                    json!({"choices": [{"index": 0, "delta": {"content": "The record "}}]}),
                    json!({"choices": [{"index": 0, "delta": {"content": "is as shown."}}]}),
                    json!({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}),
                ]
            };
            let mut out = String::new();
            for f in frames {
                out.push_str(&format!("data: {f}\n\n"));
            }
            out.push_str("data: [DONE]\n\n");
            (
                [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                out,
            )
                .into_response()
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

// ---------------------------------------------------------------------------
// One conversation, set up before the clock starts
// ---------------------------------------------------------------------------

struct Seat {
    session: AgentSession,
    security: Arc<attome_server::security::SecurityContext>,
    conversation_id: Uuid,
}

async fn seat(state: &EngineState) -> Seat {
    let db = &state.base.db;
    let owner = common::seed_user(db, true).await;
    let session = attome_ai::session::start(
        db,
        &attome_audit::audit_service(state),
        attome_ai::session::SessionStart {
            owner_user_id: owner,
            risk_ceiling: attome_ai::descriptor::RiskTier::Reversible,
            allowed_action_ids: None,
            surface: "internal",
            agent_definition_ref: None,
            integration_system_id: None,
            tainted: false,
            policy: attome_ai::session::PolicySnapshot::NONE,
        },
    )
    .await
    .expect("session");
    let conversation = conversation::create(
        db,
        NewConversation {
            agent_session_id: session.id,
            owner_user_id: owner,
            agent_definition_ref: None,
            surface: Surface::Internal,
            title: None,
        },
    )
    .await
    .expect("conversation");
    let security = Arc::new(
        attome_security::resolve_uncached(db, owner)
            .await
            .expect("security"),
    );
    Seat {
        session,
        security,
        conversation_id: conversation.id,
    }
}

struct Timed {
    conversation_id: Uuid,
    started: Instant,
    elapsed: Duration,
    outcome: Result<TerminalState, String>,
}

/// Runs one turn per seat, all at once.
async fn run_all(state: &EngineState, seats: &[Seat]) -> Vec<Timed> {
    let registry = Arc::new(ActionRegistry::new());
    let executors = Arc::new(Executors::new());
    let mut tasks = Vec::new();
    for s in seats {
        let (state, registry, executors) = (state.clone(), registry.clone(), executors.clone());
        let (session, security, conversation_id) =
            (s.session.clone(), s.security.clone(), s.conversation_id);
        tasks.push(tokio::spawn(async move {
            let started = Instant::now();
            let outcome = turn::run(
                &state,
                &registry,
                &executors,
                &TurnInputs {
                    session: &session,
                    security,
                    conversation_id,
                    step_budget: None,
                },
                "Look the record up.",
            )
            .await;
            Timed {
                conversation_id,
                started,
                elapsed: started.elapsed(),
                outcome: outcome
                    .map(|o| o.terminal_state)
                    .map_err(|e| format!("{e:?}")),
            }
        }));
    }
    let mut out = Vec::new();
    for t in tasks {
        out.push(t.await.expect("turn task"));
    }
    out
}

fn percentile(values: &mut [f64], p: f64) -> f64 {
    if values.is_empty() {
        return f64::NAN;
    }
    values.sort_by(|a, b| a.total_cmp(b));
    let rank = ((p / 100.0) * values.len() as f64).ceil() as usize;
    values[rank.clamp(1, values.len()) - 1]
}

/// Median of 50 sequential `SELECT 1` and 50 `PING`s, in milliseconds.
async fn round_trips(state: &EngineState) -> (f64, f64) {
    let mut db = Vec::new();
    let mut redis = Vec::new();
    for _ in 0..50 {
        let t = Instant::now();
        let _: i32 = sqlx::query_scalar("SELECT 1")
            .fetch_one(&state.base.db)
            .await
            .expect("select 1");
        db.push(t.elapsed().as_secs_f64() * 1000.0);
        let t = Instant::now();
        assert!(state.base.redis.ping().await, "ping");
        redis.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    (percentile(&mut db, 50.0), percentile(&mut redis, 50.0))
}

async fn state_for(model_url: String) -> Option<EngineState> {
    common::test_state_with(move |config| {
        config.inference.generation.base_url = model_url;
        config.inference.generation.model = "load-model".into();
        config.inference.generation.request_timeout_secs = 60;
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "C10-D measurement; run with --ignored against a throwaway database"]
async fn the_loop_meets_its_load_targets() {
    let latency = Duration::from_millis(env_u64("TURN_LOAD_MODEL_MS", 100));
    let latency_ms = latency.as_secs_f64() * 1000.0;

    // Phase 1 — six-step turns.
    let url = spawn_model(latency, TOOL_STEPS).await;
    let Some(state) = state_for(url).await else {
        return;
    };
    let pool = state.base.config.database.connection_number as u64;
    let concurrency = env_u64("TURN_LOAD_CONCURRENCY", pool * 2) as usize;
    attome_core::ai_runtime_switch::reload(&state.base.db).await;
    let mut seats = Vec::new();
    for _ in 0..concurrency {
        seats.push(seat(&state).await);
    }
    // The environment's floor: one database and one Redis round trip. On
    // Docker Desktop for Windows these are an order of magnitude above a
    // Linux host, and every figure below carries them.
    let (db_rtt_ms, redis_rtt_ms) = round_trips(&state).await;
    let wall = Instant::now();
    let deep = run_all(&state, &seats).await;
    let deep_wall_ms = wall.elapsed().as_secs_f64() * 1000.0;
    let model_calls = (TOOL_STEPS + 1) as f64;
    let mut overhead: Vec<f64> = deep
        .iter()
        .filter(|t| t.outcome.is_ok())
        .map(|t| (t.elapsed.as_secs_f64() * 1000.0 - model_calls * latency_ms) / model_calls)
        .collect();
    let overhead_p50 = percentile(&mut overhead, 50.0);
    let overhead_p95 = percentile(&mut overhead, 95.0);

    // Phase 2 — one-step turns, first delta at a subscriber. The answer's
    // first content frame leaves the stand-in with its whole response after
    // `latency`, so that is the model's first-byte latency here.
    let url = spawn_model(latency, 0).await;
    let Some(state2) = state_for(url).await else {
        return;
    };
    let mut seats2 = Vec::new();
    for _ in 0..concurrency {
        seats2.push(seat(&state2).await);
    }
    let mut rx = attome_ai::delta_stream::subscribe(&state2.base.config)
        .await
        .expect("delta subscription (Redis must be reachable)");
    let first_seen = Arc::new(std::sync::Mutex::new(std::collections::HashMap::<
        Uuid,
        Instant,
    >::new()));
    let collector = {
        let first_seen = first_seen.clone();
        tokio::spawn(async move {
            while let Ok(delta) = rx.recv().await {
                first_seen
                    .lock()
                    .unwrap()
                    .entry(delta.conversation_id)
                    .or_insert_with(Instant::now);
            }
        })
    };
    let shallow = run_all(&state2, &seats2).await;
    // Deltas are coalesced and published after the fact; give the last ones
    // a moment to arrive before reading.
    tokio::time::sleep(Duration::from_millis(500)).await;
    collector.abort();
    let seen = first_seen.lock().unwrap().clone();
    let mut first_delta: Vec<f64> = shallow
        .iter()
        .filter_map(|t| {
            seen.get(&t.conversation_id)
                .map(|at| at.duration_since(t.started).as_secs_f64() * 1000.0 - latency_ms)
        })
        .collect();
    let deltas_seen = first_delta.len();
    let first_delta_p50 = percentile(&mut first_delta, 50.0);
    let first_delta_p95 = percentile(&mut first_delta, 95.0);

    // Every turn completed; every event log is gapless.
    let failed: Vec<String> = deep
        .iter()
        .chain(shallow.iter())
        .filter_map(|t| match &t.outcome {
            Ok(TerminalState::Completed) => None,
            Ok(other) => Some(format!("{}: {other:?}", t.conversation_id)),
            Err(e) => Some(format!("{}: {e}", t.conversation_id)),
        })
        .collect();
    let ids: Vec<Uuid> = deep
        .iter()
        .chain(shallow.iter())
        .map(|t| t.conversation_id)
        .collect();
    let broken: Vec<(Uuid, i64, i64, i64)> = sqlx::query_as(
        "SELECT conversation_id, COUNT(*), COUNT(DISTINCT ordinal), MAX(ordinal) \
           FROM ai_conversation_event WHERE conversation_id = ANY($1) \
          GROUP BY conversation_id \
         HAVING COUNT(*) <> COUNT(DISTINCT ordinal) OR MAX(ordinal) <> COUNT(*)",
    )
    .bind(&ids)
    .fetch_all(&state.base.db)
    .await
    .expect("event log check");
    let logged: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT conversation_id) FROM ai_conversation_event \
          WHERE conversation_id = ANY($1)",
    )
    .bind(&ids)
    .fetch_one(&state.base.db)
    .await
    .expect("event log count");

    let report = json!({
        "model_latency_ms": latency_ms,
        "pool_connections": pool,
        "db_round_trip_ms": db_rtt_ms,
        "redis_round_trip_ms": redis_rtt_ms,
        "concurrent_turns": concurrency,
        "six_step": {
            "turns": deep.len(),
            "wall_ms": deep_wall_ms.round(),
            "overhead_per_step_ms": {"p50": overhead_p50, "p95": overhead_p95},
        },
        "one_step": {
            "turns": shallow.len(),
            "deltas_seen": deltas_seen,
            "first_delta_after_model_ms": {"p50": first_delta_p50, "p95": first_delta_p95},
        },
        "failed_turns": failed,
        "conversations_with_events": logged,
        "event_logs_with_gaps_or_duplicates": broken.len(),
    });
    println!("C10-D report: {report}");

    assert!(failed.is_empty(), "turns failed under load: {failed:?}");
    assert_eq!(
        logged as usize,
        ids.len(),
        "every conversation logged its events"
    );
    assert!(
        broken.is_empty(),
        "event logs with gaps or duplicates: {broken:?}"
    );
    assert_eq!(
        deltas_seen,
        shallow.len(),
        "every one-step turn delivered a delta"
    );
    assert!(
        overhead_p95 <= OVERHEAD_P95_MS,
        "overhead per step p95 {overhead_p95:.1} ms > {OVERHEAD_P95_MS} ms"
    );
    assert!(
        first_delta_p95 <= FIRST_DELTA_P95_MS,
        "first delta p95 {first_delta_p95:.1} ms > {FIRST_DELTA_P95_MS} ms after the model"
    );
}
