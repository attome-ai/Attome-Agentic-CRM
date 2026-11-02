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
            "{refused:?}"
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
