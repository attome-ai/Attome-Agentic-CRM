//! AI7-T7: a ticket's round trip between an agent and a person, end to end,
//! against a throwaway database and a scripted stand-in model.
//!
//! The agent's turn calls `handoff.to_person`; the person accepts the
//! hand-off and returns it with a note; the hand-back job
//! (`attome_ai::handback::run`, what `ai_handback` runs) resumes the agent's
//! live session with the note, and the agent hands the ticket off again.
//! Proven: the ticket's history names each step in order, with the agent's
//! reasoning; each agent hand-off records an outcome under rule
//! `ai.handoff`; the resumed turn carries the hand-back's marker and note.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-ai --test ai_handoff_roundtrip -- ai7_ --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod common;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use attome_ai::conversation::{self, NewConversation, Surface, TerminalState};
use attome_ai::execute::Executors;
use attome_ai::handback::{self, HandBackOutcome};
use attome_ai::registry::ActionRegistry;
use attome_ai::session::AgentSession;
use attome_ai::turn::{self, TurnInputs};
use attome_core::EngineState;
use attome_service::handoff::HandBack;
use axum::response::IntoResponse;
use axum::{Json, Router, routing::post};
use serde_json::{Value, json};
use uuid::Uuid;

const REASONING: &str = "The refund is over the agent's limit and needs a supervisor";
/// A hand-off row: (id, status, from_kind, from_ref, agent session, row
/// version).
type HandoffRow = (Uuid, String, String, Uuid, Option<Uuid>, i64);

const NOTE: &str = "Approved: refund the full amount, then ask them to confirm";

// ---------------------------------------------------------------------------
// The stand-in model (the shape of turn_loop.rs's, without its hooks)
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct FakeModel {
    script: Arc<Mutex<VecDeque<Value>>>,
    seen: Arc<Mutex<Vec<Value>>>,
}

impl FakeModel {
    fn new(script: Vec<Value>) -> Self {
        Self {
            script: Arc::new(Mutex::new(script.into())),
            seen: Arc::default(),
        }
    }

    fn requests(&self) -> Vec<Value> {
        self.seen.lock().unwrap().clone()
    }
}

fn says(text: &str) -> Value {
    json!({"choices": [{"message": {"content": text}, "finish_reason": "stop"}]})
}

fn wants_tool(id: &str, name: &str, arguments: &Value) -> Value {
    json!({"choices": [{
        "message": {"tool_calls": [
            {"id": id, "type": "function",
             "function": {"name": name, "arguments": arguments.to_string()}}
        ]},
        "finish_reason": "tool_calls"
    }]})
}

/// A scripted response as an OpenAI-compatible event stream, for a streamed
/// request.
fn to_sse(response: &Value) -> String {
    let choice = &response["choices"][0];
    let message = &choice["message"];
    let mut out = String::new();
    let mut push = |v: Value| out.push_str(&format!("data: {v}\n\n"));
    if let Some(text) = message["content"].as_str() {
        push(json!({"choices": [{"index": 0, "delta": {"content": text}}]}));
    }
    if let Some(calls) = message["tool_calls"].as_array() {
        for (i, call) in calls.iter().enumerate() {
            push(json!({"choices": [{"index": 0, "delta": {"tool_calls": [{
                "index": i, "id": call["id"], "type": "function",
                "function": {"name": call["function"]["name"],
                             "arguments": call["function"]["arguments"]}
            }]}}]}));
        }
    }
    push(json!({"choices": [{"index": 0, "delta": {}, "finish_reason": choice["finish_reason"]}]}));
    out.push_str("data: [DONE]\n\n");
    out
}

async fn spawn_model(model: FakeModel) -> String {
    let app = Router::new().route(
        attome_inference::CHAT_COMPLETIONS_PATH,
        post(move |Json(body): Json<Value>| {
            let model = model.clone();
            async move {
                let streamed = body["stream"] == true;
                model.seen.lock().unwrap().push(body);
                let next = model
                    .script
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or_else(|| says("SCRIPT EXHAUSTED"));
                if streamed {
                    (
                        [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                        to_sse(&next),
                    )
                        .into_response()
                } else {
                    Json(next).into_response()
                }
            }
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
// Harness
// ---------------------------------------------------------------------------

struct Trip {
    state: EngineState,
    model: FakeModel,
    owner: Uuid,
    person: Uuid,
    agent: Uuid,
    ticket: Uuid,
    session: AgentSession,
    conversation_id: Uuid,
}

fn handoff_args(ticket: Uuid, person: Uuid, summary: &str, reasoning: &str) -> Value {
    json!({
        "ticket_id": ticket,
        "to_kind": "user",
        "to_ref": person,
        "summary": summary,
        "reasoning": reasoning,
        "tool_calls": ["record.get"],
    })
}

/// The service and agent tables, an admin owner whose agent session runs the
/// turns, the person the ticket goes to, the ticket, and a model scripted by
/// `script(ticket, person)`.
async fn trip(script: impl FnOnce(Uuid, Uuid) -> Vec<Value>) -> Option<Trip> {
    let (ticket, person) = (Uuid::now_v7(), Uuid::now_v7());
    let model = FakeModel::new(script(ticket, person));
    let url = spawn_model(model.clone()).await;
    let state = common::test_state_with(move |config| {
        config.inference.generation.base_url = url;
        config.inference.generation.model = "fake-model-1".into();
        config.inference.generation.request_timeout_secs = 10;
    })
    .await?;
    attome_core::ai_runtime_switch::reload(&state.base.db).await;
    let db = state.base.db.clone();
    attome_security::seed::seed_for_tests(&db)
        .await
        .expect("security seed");
    attome_project::seed::seed_for_tests(&db)
        .await
        .expect("project seed");
    attome_service::seed::seed_for_tests(&db)
        .await
        .expect("service seed");
    let owner = common::seed_user(&db, true).await;
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active) \
         VALUES ($1, $2, $2 || '@test.invalid', true)",
    )
    .bind(person)
    .bind(attome_testkit::unique("ai7-person"))
    .execute(&db)
    .await
    .expect("the person");

    let agent_entity =
        attome_metadata::provision::ensure_entity(&db, "ai_agent", "AI Agent", Some("name"), false)
            .await
            .expect("provision ai_agent");
    for name in ["name", "status"] {
        attome_metadata::provision::ensure_attribute(
            &db,
            agent_entity,
            name,
            name,
            "text",
            false,
            false,
            true,
            true,
            None,
            None,
        )
        .await
        .expect("provision ai_agent attribute");
    }
    let agent = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO ai_agent (id, name, status, owner_ref, is_active, row_version) \
         VALUES ($1, 'service agent', 'active', $2, true, 0)",
    )
    .bind(agent)
    .bind(owner)
    .execute(&db)
    .await
    .expect("an agent");
    sqlx::query(
        "INSERT INTO service_ticket (id, ticket_number, title, priority, status) \
         VALUES ($1, $2, 'Refund over the limit', 'normal', 'open')",
    )
    .bind(ticket)
    .bind(format!("TKT-AI7-{ticket}"))
    .execute(&db)
    .await
    .expect("a ticket");
    state.entities.swap(
        attome_core::build_registry(&db)
            .await
            .expect("rebuild entity registry"),
    );

    let session = attome_ai::session::start(
        &db,
        &attome_audit::audit_service(&state),
        attome_ai::session::SessionStart {
            owner_user_id: owner,
            risk_ceiling: attome_ai::descriptor::RiskTier::Reversible,
            allowed_action_ids: Some(vec!["handoff.to_person".to_owned()]),
            surface: "internal",
            agent_definition_ref: Some(agent),
            integration_system_id: None,
            tainted: false,
            policy: attome_ai::session::PolicySnapshot::NONE,
        },
    )
    .await
    .expect("start session");
    let conversation = conversation::create(
        &db,
        NewConversation {
            agent_session_id: session.id,
            owner_user_id: owner,
            agent_definition_ref: Some(agent),
            surface: Surface::Internal,
            title: None,
        },
    )
    .await
    .expect("conversation");
    Some(Trip {
        state,
        model,
        owner,
        person,
        agent,
        ticket,
        session,
        conversation_id: conversation.id,
    })
}

impl Trip {
    fn db(&self) -> &attome_db::DbPool {
        &self.state.base.db
    }

    /// The agent's turn on `text`.
    async fn agent_turn(&self, text: &str) -> turn::TurnOutcome {
        let security = Arc::new(
            attome_security::resolve_uncached(self.db(), self.owner)
                .await
                .expect("security"),
        );
        turn::run(
            &self.state,
            &ActionRegistry::new(),
            &Executors::new(),
            &TurnInputs {
                session: &self.session,
                security,
                conversation_id: self.conversation_id,
                step_budget: None,
            },
            text,
        )
        .await
        .expect("turn::run")
    }

    /// The ticket's hand-offs, oldest first: (id, status, from_kind, from_ref,
    /// agent session, row version).
    async fn handoffs(&self) -> Vec<HandoffRow> {
        sqlx::query_as(
            "SELECT id, status, from_kind, from_ref, agent_session_ref, row_version \
               FROM service_handoff WHERE ticket_id = $1 ORDER BY created_at, id",
        )
        .bind(self.ticket)
        .fetch_all(self.db())
        .await
        .expect("hand-offs")
    }

    /// The ticket's history: its business events' texts, oldest first, from
    /// the chained ledger and the ingest table not yet chained.
    async fn history(&self) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT event_name FROM ( \
                SELECT event_name::text AS event_name, changed_on AS at FROM audit_header \
                 WHERE entity_name = 'service_ticket' AND record_id = $1 \
                   AND event_name IS NOT NULL \
                UNION ALL \
                SELECT payload->>'event_name', (payload->>'changed_on')::timestamptz \
                  FROM audit_ingest \
                 WHERE payload->>'entity_name' = 'service_ticket' \
                   AND payload->>'record_id' = $1::text \
                   AND payload->>'event_name' IS NOT NULL \
             ) events ORDER BY at",
        )
        .bind(self.ticket)
        .fetch_all(self.db())
        .await
        .expect("ticket history")
    }

    /// Outcomes recorded under rule `ai.handoff` by the session.
    async fn handoff_outcomes(&self) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM outcome \
              WHERE rule_ref = 'ai.handoff' AND agent_session_ref = $1",
        )
        .bind(self.session.id)
        .fetch_one(self.db())
        .await
        .expect("outcomes")
    }
}

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

/// Agent → person → agent: the hand-off, its acceptance, the return with a
/// note and the resumed agent's second hand-off are each on the ticket, and
/// each agent hand-off left an outcome under `ai.handoff`.
#[tokio::test]
async fn ai7_roundtrip_agent_person_agent() {
    let t = skip_if_no_db(
        trip(|ticket, person| {
            vec![
                wants_tool(
                    "call-1",
                    "handoff.to_person",
                    &handoff_args(ticket, person, "Customer wants a refund of 900", REASONING),
                ),
                says("I handed the ticket to a supervisor."),
                wants_tool(
                    "call-2",
                    "handoff.to_person",
                    &handoff_args(
                        ticket,
                        person,
                        "Refund approved and issued; the customer should confirm by phone",
                        "Only a person can call the customer to confirm",
                    ),
                ),
                says("The refund is done; I asked the supervisor to call the customer."),
            ]
        })
        .await,
    );
    let Some(t) = t else { return };

    // The agent hands the ticket to the person.
    let first = t
        .agent_turn("Handle ticket: the customer asks for a refund of 900.")
        .await;
    assert_eq!(first.terminal_state, TerminalState::Completed);
    let handoffs = t.handoffs().await;
    assert_eq!(handoffs.len(), 1, "the agent's tool call made one hand-off");
    let (handoff_id, status, from_kind, from_ref, session_ref, version) = handoffs[0].clone();
    assert_eq!(status, "pending");
    assert_eq!(from_kind, "agent");
    assert_eq!(from_ref, t.agent);
    assert_eq!(session_ref, Some(t.session.id));

    // The person accepts it and gives it back with a note.
    let accepted = attome_service::handoff::accept(&t.state, t.person, handoff_id, version)
        .await
        .expect("the person accepts");
    let returned = attome_service::handoff::give_back(
        &t.state,
        t.person,
        handoff_id,
        NOTE,
        accepted.row_version,
    )
    .await
    .expect("the person gives it back");
    assert_eq!(returned.status, "returned");
    // The hand-back job resumes the live session with the note.
    let outcome = handback::run(
        &t.state,
        &HandBack {
            handoff_id,
            note: NOTE.to_owned(),
            returned_by: t.person,
        },
    )
    .await
    .expect("hand-back");
    assert_eq!(
        outcome,
        HandBackOutcome::Resumed {
            conversation_id: t.conversation_id
        }
    );
    let resumed_turn = t
        .model
        .requests()
        .into_iter()
        .nth(2)
        .expect("the resumed turn reached the model")
        .to_string();
    assert!(resumed_turn.contains(&handback::marker(handoff_id)));
    assert!(resumed_turn.contains(NOTE));

    // A retried job does nothing.
    let again = handback::run(
        &t.state,
        &HandBack {
            handoff_id,
            note: NOTE.to_owned(),
            returned_by: t.person,
        },
    )
    .await
    .expect("retried hand-back");
    assert!(matches!(again, HandBackOutcome::Skipped(_)));

    // The ticket's history: handed off, accepted, returned, handed off again.
    let history = t.history().await;
    assert_eq!(history.len(), 4, "{history:#?}");
    assert!(history[0].starts_with("Handed off by agent to user"));
    assert!(history[1].starts_with("Hand-off accepted"));
    assert!(history[2].starts_with("Returned to the agent"));
    assert!(history[2].contains(NOTE));
    assert!(history[3].starts_with("Handed off by agent to user"));

    let handoffs = t.handoffs().await;
    assert_eq!(handoffs.len(), 2);
    assert_eq!(handoffs[0].1, "returned");
    assert_eq!(handoffs[1].1, "pending");
    assert_eq!(
        t.handoff_outcomes().await,
        2,
        "one outcome per agent hand-off"
    );
}

/// The ticket's history entry for the agent's hand-off carries its
/// reasoning.
#[tokio::test]
async fn ai7_handoff_history_shows_reasoning() {
    let t = skip_if_no_db(
        trip(|ticket, person| {
            vec![
                wants_tool(
                    "call-1",
                    "handoff.to_person",
                    &handoff_args(ticket, person, "Customer wants a refund of 900", REASONING),
                ),
                says("Handed off."),
            ]
        })
        .await,
    );
    let Some(t) = t else { return };
    let first = t
        .agent_turn("Handle ticket: the customer asks for a refund of 900.")
        .await;
    assert_eq!(first.terminal_state, TerminalState::Completed);
    let history = t.history().await;
    assert_eq!(history.len(), 1, "{history:#?}");
    assert!(
        history[0].contains(&format!("Reasoning: {REASONING}")),
        "{history:#?}"
    );
}

/// `Some` with a database, else `None` after saying why (the
/// `skip_if_no_db!` posture for a value built by a closure-taking helper).
fn skip_if_no_db(trip: Option<Trip>) -> Option<Trip> {
    if trip.is_none() {
        eprintln!("skipping: no test database (set DATABASE_URL)");
    }
    trip
}
