//! A31-T4: a leaver's records move to their manager: the person holding the
//! position above theirs, through the mass reassign, as the administrator
//! who disabled them. Records someone else owns stay.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_security::ownership::LeaverRule;
use attome_testapp::{TestApp, seed_user};
use serde_json::Value;
use uuid::Uuid;

// feature: A31
#[test]
fn leaver_records_move_to_their_manager() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packs/crm/changesets");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        files.sort();
        for file in &files {
            let value: Value =
                serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
            attome_api::changeset::boot::apply_pack_document(&app.state, &value)
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        }

        let manager = seed_user(app.db(), "leaver-manager").await.id;
        let leaver = seed_user(app.db(), "leaver").await.id;
        let other = seed_user(app.db(), "leaver-other").await.id;
        let (top, below) = (Uuid::now_v7(), Uuid::now_v7());
        for (id, parent) in [(top, None), (below, Some(top))] {
            sqlx::query("INSERT INTO position (id, name, parent_position_ref) VALUES ($1, $2, $3)")
                .bind(id)
                .bind(format!("Leaver test {}", Uuid::now_v7().simple()))
                .bind(parent)
                .execute(app.db())
                .await
                .unwrap();
        }
        for (user, position) in [(manager, top), (leaver, below)] {
            sqlx::query(
                "INSERT INTO user_account_mm_position (id, user_ref, position_ref) \
                 VALUES ($1, $2, $3)",
            )
            .bind(Uuid::now_v7())
            .bind(user)
            .bind(position)
            .execute(app.db())
            .await
            .unwrap();
        }
        let mut theirs = Vec::new();
        for (owner, name) in [(leaver, "Left A"), (leaver, "Left B"), (other, "Kept")] {
            let id: Uuid = sqlx::query_scalar(
                "INSERT INTO account (name, owner_ref, owner_type) VALUES ($1, $2, 0) RETURNING id",
            )
            .bind(format!("{name} {}", Uuid::now_v7().simple()))
            .bind(owner)
            .fetch_one(app.db())
            .await
            .unwrap();
            theirs.push((id, owner));
        }

        let started = attome_api::leaver::reassign_with(
            &app.state,
            app.admin.id,
            leaver,
            &[("account".to_owned(), LeaverRule::Manager)],
        )
        .await
        .unwrap();
        assert_eq!(started, 1, "one mass reassign for account");

        for (id, was) in theirs {
            let owner: Uuid = sqlx::query_scalar("SELECT owner_ref FROM account WHERE id = $1")
                .bind(id)
                .fetch_one(app.db())
                .await
                .unwrap();
            if was == leaver {
                assert_eq!(owner, manager, "a leaver's account goes to the manager");
            } else {
                assert_eq!(owner, other, "someone else's account stays");
            }
        }

        // A rule naming nobody leaves the records where they are.
        let lonely = seed_user(app.db(), "leaver-lonely").await.id;
        assert_eq!(
            attome_api::leaver::reassign_with(
                &app.state,
                app.admin.id,
                lonely,
                &[("account".to_owned(), LeaverRule::Manager)],
            )
            .await
            .unwrap(),
            0
        );
    });
}
