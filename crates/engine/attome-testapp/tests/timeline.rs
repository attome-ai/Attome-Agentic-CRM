//! B1-T1: the record timeline merges approvals, flow runs and agent runs with
//! the existing sources, carries who or what made each entry, rolls in the
//! related records `records.timeline_roll_in` names, filters inside every
//! source, and pages its first page quickly on a record with 50,000 events.
//!
//! Audit, approval and flow-run rows are written directly: this binary's
//! throwaway database (guidelines §4's test exemption).

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::time::{Duration, Instant};

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

async fn create_entity(app: &TestApp, name: &str) -> Uuid {
    let (status, body) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": name, "name": name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["id"].as_str().unwrap().parse().unwrap()
}

async fn add_field(app: &TestApp, entity_id: Uuid, field: Value) {
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/v1/admin/entities/{entity_id}/fields"),
            Some(field),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

async fn create_record(app: &TestApp, entity: &str, body: Value) -> Uuid {
    let (status, created) = app
        .request(Method::POST, &format!("/api/v1/{entity}"), Some(body))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    created["id"].as_str().unwrap().parse().unwrap()
}

/// One audit row on a record, `minutes` ago.
#[allow(
    clippy::too_many_arguments,
    reason = "one fixture row's columns, named at each call"
)]
async fn audit(
    app: &TestApp,
    entity: &str,
    record: Uuid,
    minutes: i32,
    user: Uuid,
    comment: &str,
    initiator: i16,
    session: Option<Uuid>,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO audit_header (entity_name, record_id, operation, changed_on, user_id, \
                                   user_display_name, event_comment, initiator, \
                                   agent_session_id, agent_action_id) \
         VALUES ($1, $2, 1, now() - make_interval(mins => $3), $4, 'Tester', $5, $6, $7, \
                 CASE WHEN $7::uuid IS NULL THEN NULL ELSE 'records.update' END) \
         RETURNING id",
    )
    .bind(entity)
    .bind(record)
    .bind(minutes)
    .bind(user)
    .bind(comment)
    .bind(initiator)
    .bind(session)
    .fetch_one(app.db())
    .await
    .unwrap()
}

async fn timeline(app: &TestApp, entity: &str, record: Uuid, query: &str) -> Value {
    let (status, body) = app
        .request(
            Method::GET,
            &format!("/api/v1/{entity}/{record}/timeline?page_size=200{query}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{query}: {body}");
    body
}

fn items(page: &Value) -> Vec<Value> {
    page["items"].as_array().unwrap().clone()
}

// feature: B1
#[test]
fn timeline_merges_sources_with_provenance_and_rolls_in() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let token = Uuid::now_v7().simple().to_string();
        let parent = format!("tl_acct_{}", &token[..12]);
        let child = format!("tl_kid_{}", &token[..12]);
        let parent_id = create_entity(&app, &parent).await;
        add_field(
            &app,
            parent_id,
            json!({ "logicalname": "code", "name": "code", "field_type": "text" }),
        )
        .await;
        let child_id = create_entity(&app, &child).await;
        add_field(
            &app,
            child_id,
            json!({ "logicalname": "acct_ref", "name": "acct_ref",
                    "field_type": "lookup", "lookup_entity_ref": parent_id }),
        )
        .await;
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);
        let account = create_record(&app, &parent, json!({ "code": "A1" })).await;
        let contact = create_record(&app, &child, json!({ "acct_ref": account })).await;
        let me = app.admin.id;

        // A person's change, an agent's change in its session, an approval
        // and a flow run on the account; a change on its contact.
        let session: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_session (owner_user_id, surface) VALUES ($1, 'chat') RETURNING id",
        )
        .bind(me)
        .fetch_one(app.db())
        .await
        .unwrap();
        let word = format!("w{}", &token[..10]);
        let by_person = audit(&app, &parent, account, 50, me, &word, 0, None).await;
        let by_agent = audit(
            &app,
            &parent,
            account,
            40,
            me,
            "agent edit",
            1,
            Some(session),
        )
        .await;
        let on_contact = audit(&app, &child, contact, 30, me, "contact edit", 0, None).await;
        let approval: Uuid = sqlx::query_scalar(
            "INSERT INTO approval_request (action_type, payload, requested_by, regarding_entity, \
                                           regarding_id, expires_at, requested_at) \
             VALUES ('records.bulk_edit', '{}'::jsonb, $1, $2, $3, now() + interval '1 day', \
                     now() - interval '20 minutes') RETURNING id",
        )
        .bind(me)
        .bind(&parent)
        .bind(account)
        .fetch_one(app.db())
        .await
        .unwrap();
        let definition: Uuid = sqlx::query_scalar(
            "INSERT INTO workflow_definition (logicalname, name, owner_layer) \
             VALUES ($1, 'Welcome account', 'customer') RETURNING id",
        )
        .bind(format!("welcome_{}", &token[..12]))
        .fetch_one(app.db())
        .await
        .unwrap();
        let version: Uuid = sqlx::query_scalar(
            "INSERT INTO workflow_definition_version (definition_id, version_number, status) \
             VALUES ($1, 1, 'published') RETURNING id",
        )
        .bind(definition)
        .fetch_one(app.db())
        .await
        .unwrap();
        let flow_run: Uuid = sqlx::query_scalar(
            "INSERT INTO workflow_instance (definition_version_id, correlation_entity_id, status, \
                                            started_by, started_at) \
             VALUES ($1, $2, 'completed', $3, now() - interval '10 minutes') RETURNING id",
        )
        .bind(version)
        .bind(account)
        .bind(me)
        .fetch_one(app.db())
        .await
        .unwrap();

        let page = timeline(&app, &parent, account, "").await;
        let all = items(&page);
        let find = |kind: &str, id: Uuid| {
            all.iter()
                .find(|e| e["kind"] == kind && e["source_id"] == json!(id))
                .cloned()
                .unwrap_or_else(|| panic!("{kind} {id} is on the timeline: {page}"))
        };
        let person = find("audit_event", by_person);
        assert_eq!(person["actor"], json!(me));
        assert_eq!(person["actor_kind"], "person");
        assert_eq!(
            person["source_record"],
            json!({"entity": parent, "id": account})
        );
        let agent_change = find("audit_event", by_agent);
        assert_eq!(agent_change["actor_kind"], "agent");
        assert_eq!(agent_change["run_id"], json!(session));
        let run = find("agent_run", session);
        assert_eq!(run["actor_kind"], "agent");
        assert_eq!(run["actor"], json!(me), "the person the agent acted for");
        assert_eq!(run["detail"]["changes"], 1);
        assert_eq!(run["detail"]["actions"], json!(["records.update"]));
        let asked = find("approval", approval);
        assert_eq!(asked["detail"]["action_type"], "records.bulk_edit");
        assert!(
            asked["detail"].get("payload").is_none(),
            "never the payload"
        );
        let flow = find("flow_run", flow_run);
        assert_eq!(flow["actor_kind"], "flow");
        assert_eq!(flow["run_id"], json!(flow_run));
        assert_eq!(flow["summary"], "Flow: Welcome account (completed)");
        assert!(
            all.iter().all(|e| e["source_id"] != json!(on_contact)),
            "nothing rolls in until the deployment says so"
        );
        // Newest first: the flow run, the approval, the agent, the person.
        let order: Vec<&Value> = all
            .iter()
            .filter(|e| {
                [
                    json!(flow_run),
                    json!(approval),
                    json!(by_agent),
                    json!(by_person),
                ]
                .contains(&e["source_id"])
            })
            .map(|e| &e["source_id"])
            .collect();
        assert_eq!(
            order,
            vec![
                &json!(flow_run),
                &json!(approval),
                &json!(by_agent),
                &json!(by_person)
            ]
        );

        // Roll in the account's contacts.
        let mut roll_in = serde_json::Map::new();
        roll_in.insert(
            parent.clone(),
            json!([{"entity": child, "via": "acct_ref"}]),
        );
        let (status, body) = app
            .request(
                Method::PUT,
                "/api/v1/admin/settings/records.timeline_roll_in",
                Some(json!({
                    "scope": "deployment",
                    "value": Value::Object(roll_in)
                })),
            )
            .await;
        assert!(status.is_success(), "{status} {body}");
        let rolled = items(&timeline(&app, &parent, account, "").await);
        let from_contact = rolled
            .iter()
            .find(|e| e["source_id"] == json!(on_contact))
            .unwrap_or_else(|| panic!("the contact's change rolls in: {rolled:?}"));
        assert_eq!(
            from_contact["source_record"],
            json!({"entity": child, "id": contact})
        );
        let own_only = items(&timeline(&app, &parent, account, "&related=false").await);
        assert!(own_only.iter().all(|e| e["source_id"] != json!(on_contact)));

        // Filters run inside each source.
        let only = items(&timeline(&app, &parent, account, "&kinds=approval").await);
        assert_eq!(only.len(), 1, "{only:?}");
        assert_eq!(only[0]["kind"], "approval");
        let found = items(&timeline(&app, &parent, account, &format!("&q={word}")).await);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0]["source_id"], json!(by_person));
        let nobody = items(
            &timeline(
                &app,
                &parent,
                account,
                &format!("&actor={}", Uuid::now_v7()),
            )
            .await,
        );
        assert!(nobody.is_empty(), "{nobody:?}");
        let later = items(
            &timeline(
                &app,
                &parent,
                account,
                "&from=2100-01-01T00:00:00Z&to=2100-01-02T00:00:00Z",
            )
            .await,
        );
        assert!(later.is_empty(), "{later:?}");
        let emails = items(&timeline(&app, &parent, account, "&channel=email").await);
        assert!(
            emails.iter().all(|e| e["kind"] == "communication"),
            "{emails:?}"
        );
        let (status, _) = app
            .request(
                Method::GET,
                &format!(
                    "/api/v1/{parent}/{account}/timeline?from=2026-10-02T00:00:00Z&to=2026-10-01T00:00:00Z"
                ),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // Paging in small pages returns every entry once.
        let mut seen = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let query = match &cursor {
                Some(c) => format!("/api/v1/{parent}/{account}/timeline?page_size=2&cursor={c}"),
                None => format!("/api/v1/{parent}/{account}/timeline?page_size=2"),
            };
            let (status, page) = app.request(Method::GET, &query, None).await;
            assert_eq!(status, StatusCode::OK, "{page}");
            for e in items(&page) {
                seen.push((e["kind"].clone(), e["source_id"].clone()));
            }
            match page["next_cursor"].as_str() {
                Some(next) => cursor = Some(next.to_owned()),
                None => break,
            }
        }
        assert_eq!(seen.len(), rolled.len(), "{seen:?}");
        let unique: std::collections::HashSet<_> = seen.iter().collect();
        assert_eq!(unique.len(), seen.len(), "no entry twice");
    });
}

// feature: B1
#[test]
fn first_page_is_fast_on_a_record_with_50000_events() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let token = Uuid::now_v7().simple().to_string();
        let entity = format!("tl_busy_{}", &token[..12]);
        let entity_id = create_entity(&app, &entity).await;
        add_field(
            &app,
            entity_id,
            json!({ "logicalname": "code", "name": "code", "field_type": "text" }),
        )
        .await;
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);
        let record = create_record(&app, &entity, json!({ "code": "busy" })).await;
        sqlx::query(
            "INSERT INTO audit_header (entity_name, record_id, operation, changed_on, user_id, \
                                       user_display_name, event_comment) \
             SELECT $1, $2, 1, now() - make_interval(secs => g), $3, 'Tester', 'bulk ' || g \
               FROM generate_series(1, 50000) g",
        )
        .bind(&entity)
        .bind(record)
        .bind(app.admin.id)
        .execute(app.db())
        .await
        .unwrap();
        sqlx::query("ANALYZE audit_header")
            .execute(app.db())
            .await
            .unwrap();

        // The audit source reads the record's newest rows from the index.
        let plan: Vec<String> = sqlx::query_scalar(
            "EXPLAIN SELECT h.id FROM audit_header h \
              WHERE h.entity_name = $1 AND h.record_id = $2 AND h.changed_on IS NOT NULL \
              ORDER BY h.changed_on DESC, h.id DESC LIMIT 51",
        )
        .bind(&entity)
        .bind(record)
        .fetch_all(app.db())
        .await
        .unwrap();
        let plan = plan.join("\n");
        assert!(
            plan.contains("audit_header_record_timeline_idx"),
            "the timeline index serves the audit source:\n{plan}"
        );
        assert!(
            !plan.contains("Sort"),
            "no sort of the record's rows:\n{plan}"
        );

        let path = format!("/api/v1/{entity}/{record}/timeline?page_size=50");
        let (status, _) = app.request(Method::GET, &path, None).await;
        assert_eq!(status, StatusCode::OK);
        let started = Instant::now();
        let (status, page) = app.request(Method::GET, &path, None).await;
        let took = started.elapsed();
        assert_eq!(status, StatusCode::OK, "{page}");
        assert_eq!(page["items"].as_array().unwrap().len(), 50);
        assert!(page["next_cursor"].is_string());
        assert!(
            took < Duration::from_millis(300),
            "first page took {took:?} on 50,000 events"
        );
    });
}

// feature: B1
#[test]
fn pinned_entries_are_marked_and_listed_alone() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let token = Uuid::now_v7().simple().to_string();
        let entity = format!("tl_pin_{}", &token[..12]);
        let entity_id = create_entity(&app, &entity).await;
        add_field(
            &app,
            entity_id,
            json!({ "logicalname": "code", "name": "code", "field_type": "text" }),
        )
        .await;
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);
        let record = create_record(&app, &entity, json!({ "code": "P" })).await;
        let me = app.admin.id;
        let older = audit(&app, &entity, record, 30, me, "older", 0, None).await;
        let newer = audit(&app, &entity, record, 10, me, "newer", 0, None).await;

        let pin = format!("/api/v1/{entity}/{record}/timeline/pins/audit_event/{older}");
        let (status, body) = app.request(Method::PUT, &pin, None).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        let (status, _) = app.request(Method::PUT, &pin, None).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "pinning twice is fine");

        let all = items(&timeline(&app, &entity, record, "").await);
        let flag = |id: Uuid| {
            all.iter()
                .find(|e| e["source_id"] == json!(id))
                .map(|e| e["pinned"].clone())
                .unwrap()
        };
        assert_eq!(flag(older), json!(true));
        assert_eq!(flag(newer), json!(false));
        let only = items(&timeline(&app, &entity, record, "&pinned_only=true").await);
        assert_eq!(only.len(), 1, "{only:?}");
        assert_eq!(only[0]["source_id"], json!(older));

        let (status, _) = app.request(Method::DELETE, &pin, None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let none = items(&timeline(&app, &entity, record, "&pinned_only=true").await);
        assert!(none.is_empty(), "{none:?}");

        let (status, _) = app
            .request(
                Method::PUT,
                &format!("/api/v1/{entity}/{record}/timeline/pins/bogus/{older}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    });
}
