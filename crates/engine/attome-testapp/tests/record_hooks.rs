//! Y10-T2: hooks at the record write pipeline's stages: a before-save hook
//! changes a value or rejects the save with its message (a 422, nothing
//! written), and an after-save hook runs once per committed write.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use attome_core::EngineState;
use attome_core::record_hooks::{HookEvent, HookFuture, HookOutcome, HookStage, RecordHook};
use attome_testapp::TestApp;
use attome_types::AppError;
use serde_json::{Map, Value, json};

/// Rejects a name holding "forbidden"; otherwise marks it checked.
struct NameCheck;

impl RecordHook for NameCheck {
    fn name(&self) -> &str {
        "test.name_check"
    }
    fn entity(&self) -> &str {
        "account"
    }
    fn stage(&self) -> HookStage {
        HookStage::BeforeSave
    }
    fn run<'a>(&'a self, _state: &'a EngineState, event: HookEvent<'a>) -> HookFuture<'a> {
        Box::pin(async move {
            let name = event
                .values
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if name.contains("forbidden") {
                return Ok(HookOutcome::Reject("this name is not allowed".into()));
            }
            if !event.is_create {
                return Ok(HookOutcome::Continue);
            }
            let mut set = Map::new();
            set.insert("name".into(), json!(format!("{name} (checked)")));
            Ok(HookOutcome::Change(set))
        })
    }
}

/// Counts committed creates.
struct Counter(Arc<AtomicUsize>);

impl RecordHook for Counter {
    fn name(&self) -> &str {
        "test.counter"
    }
    fn entity(&self) -> &str {
        "account"
    }
    fn stage(&self) -> HookStage {
        HookStage::AfterSave
    }
    fn run<'a>(&'a self, _state: &'a EngineState, event: HookEvent<'a>) -> HookFuture<'a> {
        Box::pin(async move {
            assert!(
                event.record_id.is_some(),
                "after the save the record has its id"
            );
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(HookOutcome::Continue)
        })
    }
}

// feature: Y10
#[test]
fn hooks_change_reject_and_follow_the_save() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        app.install_packs(&["crm"]).await;
        let saves = Arc::new(AtomicUsize::new(0));
        let mut state = app.state.clone();
        state.record_hooks = Arc::new(vec![
            Arc::new(NameCheck) as Arc<dyn RecordHook>,
            Arc::new(Counter(saves.clone())),
        ]);
        let ctx = state
            .base
            .security
            .resolve(app.admin.id)
            .await
            .expect("ctx");

        let tag = uuid::Uuid::now_v7().simple().to_string();
        let (id, _) = attome_records::entity_crud::create_record_for(
            &state,
            &ctx,
            app.admin.id,
            "account",
            json!({ "name": format!("Hooked {tag}") }),
        )
        .await
        .expect("a create the hook changes");
        let stored: String = sqlx::query_scalar("SELECT name FROM account WHERE id = $1")
            .bind(id)
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(stored, format!("Hooked {tag} (checked)"));
        assert_eq!(saves.load(Ordering::SeqCst), 1);

        let refused = attome_records::entity_crud::create_record_for(
            &state,
            &ctx,
            app.admin.id,
            "account",
            json!({ "name": format!("forbidden {tag}") }),
        )
        .await;
        assert!(
            matches!(&refused, Err(AppError::Validation(m)) if m == "this name is not allowed"),
            "the hook refuses the save with its message"
        );
        let written: i64 = sqlx::query_scalar("SELECT count(*) FROM account WHERE name = $1")
            .bind(format!("forbidden {tag}"))
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(written, 0, "a rejected save writes nothing");
        assert_eq!(
            saves.load(Ordering::SeqCst),
            1,
            "no after-save for a rejected write"
        );

        // The engine without hooks is unchanged.
        let (plain, _) = attome_records::entity_crud::create_record_for(
            &app.state,
            &ctx,
            app.admin.id,
            "account",
            json!({ "name": format!("Plain {tag}") }),
        )
        .await
        .expect("a create without hooks");
        let stored: String = sqlx::query_scalar("SELECT name FROM account WHERE id = $1")
            .bind(plain)
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(stored, format!("Plain {tag}"));
    });
}

/// A hook whose own work runs the same stage again, as a hook writing the
/// record it watches would.
struct Recursive(Arc<AtomicUsize>);

impl RecordHook for Recursive {
    fn name(&self) -> &str {
        "test.recursive"
    }
    fn entity(&self) -> &str {
        "loop_entity"
    }
    fn stage(&self) -> HookStage {
        HookStage::BeforeSave
    }
    fn run<'a>(&'a self, state: &'a EngineState, event: HookEvent<'a>) -> HookFuture<'a> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::SeqCst);
            attome_core::record_hooks::run_stage(state, HookStage::BeforeSave, event).await?;
            Ok(HookOutcome::Continue)
        })
    }
}

// feature: Y10
#[test]
fn recursive_hooks_stop_at_depth_eight() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        app.install_packs(&["crm"]).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let mut state = app.state.clone();
        state.record_hooks = Arc::new(vec![
            Arc::new(Recursive(calls.clone())) as Arc<dyn RecordHook>
        ]);
        let values = Map::new();
        let refused = attome_core::record_hooks::run_stage(
            &state,
            HookStage::BeforeSave,
            HookEvent {
                entity: "loop_entity",
                record_id: None,
                is_create: true,
                values: &values,
                previous: None,
                actor: None,
            },
        )
        .await;
        assert!(
            matches!(refused, Err(AppError::Validation(_))),
            "{refused:?}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            attome_core::record_hooks::MAX_HOOK_DEPTH as usize,
            "the hook ran at depths 1 to 8, then the ninth level was refused"
        );
        assert_eq!(attome_core::record_hooks::current_depth(), 0);
    });
}

/// Counts after-commit runs and rejects every one (which cannot undo a
/// committed write).
struct AfterCommit(Arc<AtomicUsize>);

impl RecordHook for AfterCommit {
    fn name(&self) -> &str {
        "test.after_commit"
    }
    fn entity(&self) -> &str {
        "account"
    }
    fn stage(&self) -> HookStage {
        HookStage::AfterCommit
    }
    fn run<'a>(&'a self, _state: &'a EngineState, event: HookEvent<'a>) -> HookFuture<'a> {
        Box::pin(async move {
            assert!(event.values.contains_key("name"), "the stored row");
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(HookOutcome::Reject("too late to refuse".into()))
        })
    }
}

// feature: Y10
#[test]
fn after_commit_hooks_run_as_a_job_once_the_write_commits() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        app.install_packs(&["crm"]).await;
        let runs = Arc::new(AtomicUsize::new(0));
        let mut state = app.state.clone();
        state.record_hooks = Arc::new(vec![
            Arc::new(AfterCommit(runs.clone())) as Arc<dyn RecordHook>
        ]);
        let ctx = state
            .base
            .security
            .resolve(app.admin.id)
            .await
            .expect("ctx");
        let tag = uuid::Uuid::now_v7().simple().to_string();
        let (id, _) = attome_records::entity_crud::create_record_for(
            &state,
            &ctx,
            app.admin.id,
            "account",
            json!({ "name": format!("Committed {tag}") }),
        )
        .await
        .expect("the create commits");
        assert_eq!(runs.load(Ordering::SeqCst), 0, "not run in the write");

        let queued: Vec<Value> = sqlx::query_scalar(
            "SELECT job FROM apalis.jobs \
              WHERE job::text LIKE '%record_hook_after_commit%' AND job::text LIKE '%' || $1 || '%'",
        )
        .bind(id.to_string())
        .fetch_all(app.db())
        .await
        .unwrap();
        assert_eq!(queued.len(), 1, "one job for the committed write");

        let payload = attome_core::record_hooks::AfterCommitPayload {
            entity: "account".into(),
            record_id: id,
            is_create: true,
            values: Map::from_iter([("name".to_owned(), json!(format!("Committed {tag}")))]),
            previous: None,
            actor: Some(app.admin.id),
        };
        attome_core::record_hooks::run_after_commit(&state, &payload)
            .await
            .expect("a rejection after the commit is only logged");
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        let kept: i64 = sqlx::query_scalar("SELECT count(*) FROM account WHERE id = $1")
            .bind(id)
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(kept, 1, "the committed write stays");

        // Without such a hook nothing is queued.
        let (plain, _) = attome_records::entity_crud::create_record_for(
            &app.state,
            &ctx,
            app.admin.id,
            "account",
            json!({ "name": format!("Plain {tag}") }),
        )
        .await
        .expect("a create without hooks");
        let none: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM apalis.jobs \
              WHERE job::text LIKE '%record_hook_after_commit%' AND job::text LIKE '%' || $1 || '%'",
        )
        .bind(plain.to_string())
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(none, 0);
    });
}

/// Y10-T4: counts the batches an after-commit hook is handed and their sizes.
struct BatchCounter(Arc<std::sync::Mutex<Vec<usize>>>);

impl RecordHook for BatchCounter {
    fn name(&self) -> &str {
        "test.batch_counter"
    }
    fn entity(&self) -> &str {
        "account"
    }
    fn stage(&self) -> HookStage {
        HookStage::AfterCommit
    }
    fn run<'a>(&'a self, _state: &'a EngineState, _event: HookEvent<'a>) -> HookFuture<'a> {
        Box::pin(async move { Ok(HookOutcome::Continue) })
    }
    fn run_batch<'a>(
        &'a self,
        _state: &'a EngineState,
        events: &'a [HookEvent<'a>],
    ) -> attome_core::record_hooks::BatchFuture<'a> {
        Box::pin(async move {
            self.0.lock().unwrap().push(events.len());
            Ok(())
        })
    }
}

// feature: Y10
#[test]
fn bulk_writes_reach_after_commit_hooks_in_one_batch() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        app.install_packs(&["crm"]).await;
        sqlx::query("DELETE FROM record_hook_outbox")
            .execute(app.db())
            .await
            .unwrap();
        let batches = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut state = app.state.clone();
        state.record_hooks = Arc::new(vec![
            Arc::new(BatchCounter(batches.clone())) as Arc<dyn RecordHook>
        ]);
        let ctx = state
            .base
            .security
            .resolve(app.admin.id)
            .await
            .expect("ctx");
        let tag = uuid::Uuid::now_v7().simple().to_string();
        attome_core::record_hooks::in_bulk(async {
            for n in 0..3 {
                attome_records::entity_crud::create_record_for(
                    &state,
                    &ctx,
                    app.admin.id,
                    "account",
                    json!({ "name": format!("Bulk {tag} {n}") }),
                )
                .await
                .expect("a bulk create");
            }
        })
        .await;
        let waiting: i64 = sqlx::query_scalar("SELECT count(*) FROM record_hook_outbox")
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(waiting, 3, "each write left its payload in the outbox");
        let delivered = attome_core::record_hooks::drain_outbox(&state)
            .await
            .unwrap();
        assert_eq!(delivered, 3);
        assert_eq!(*batches.lock().unwrap(), vec![3], "one call for the three");
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM record_hook_outbox")
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(left, 0);
    });
}
