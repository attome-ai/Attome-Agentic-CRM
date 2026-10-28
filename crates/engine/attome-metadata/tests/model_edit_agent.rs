//! Y11-T14: inside an agent's scope, an edit of an item the platform owns is
//! refused with 403, while a customer item stays editable.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_core::agent_scope::{self, AgentScope};
use attome_metadata::model_edit::{self, EditRequest};
use attome_testkit::migrated_pool_or_skip;
use attome_types::AppError;
use uuid::Uuid;

fn agent() -> AgentScope {
    AgentScope {
        session_id: Uuid::now_v7(),
        action_id: "model.form.edit".to_owned(),
    }
}

#[tokio::test]
async fn agent_cannot_edit_platform_item() {
    let pool = migrated_pool_or_skip!(2);
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO metadata_object (id, kind, name, app, owner_layer) \
         VALUES ($1, 'form', $2, 'platform', 'platform')",
    )
    .bind(id)
    .bind(format!("platform_form_{}", id.simple()))
    .execute(&pool)
    .await
    .expect("a platform item");
    let kind = model_edit::registry().get("form").expect("the form kind");

    let mut tx = attome_db::tx::begin(&pool).await.expect("begin");
    let edited = agent_scope::scope(
        agent(),
        model_edit::edit(
            &pool,
            &mut tx,
            kind.as_ref(),
            EditRequest {
                id,
                base_hash: String::new(),
                name: None,
                commands: Vec::new(),
            },
            None,
        ),
    )
    .await;
    assert!(
        matches!(edited, Err(AppError::Forbidden)),
        "an agent edit of a platform item is refused: {edited:?}"
    );
    drop(tx);

    sqlx::query("DELETE FROM metadata_object WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .expect("clean up");
}
