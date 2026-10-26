//! G17-T10: a person ten minutes late to their shift scores under 100%
//! adherence, and a member of another planning group cannot watch this
//! group live.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::{TestApp, seed_user};
use attome_workforce::adherence::{PresenceSource, ScheduleCache, record_minute, roll_up_day};
use axum::http::{Method, StatusCode};
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

const PACKS: [&str; 1] = ["workforce"];

async fn install(app: &TestApp) {
    for pack in PACKS {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../packs")
            .join(pack)
            .join("changesets");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        files.sort();
        for file in &files {
            let value: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
            attome_api::changeset::boot::apply_pack_document(&app.state, &value)
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        }
    }
}

async fn grant(app: &TestApp, user: Uuid, key: &str) {
    attome_security::db::ensure_privilege(
        app.db(),
        key,
        key,
        "test grant",
        attome_core::changeset::Layer::Project,
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         SELECT uuidv7(), $1, id, true, now() FROM privilege WHERE key = $2",
    )
    .bind(user)
    .bind(key)
    .execute(app.db())
    .await
    .unwrap();
}

async fn group(app: &TestApp, members: &[Uuid]) -> Uuid {
    let group: Uuid = sqlx::query_scalar(
        "INSERT INTO wfm_planning_group (id, name, is_active, row_version) \
         VALUES (uuidv7(), 'Team', true, 0) RETURNING id",
    )
    .fetch_one(app.db())
    .await
    .unwrap();
    for member in members {
        sqlx::query(
            "INSERT INTO wfm_group_member (id, planning_group_ref, user_ref, is_active, row_version) \
             VALUES (uuidv7(), $1, $2, true, 0)",
        )
        .bind(group)
        .bind(member)
        .execute(app.db())
        .await
        .unwrap();
    }
    group
}

/// Offline for the first ten minutes of the shift, then available.
struct LateStart {
    user: Uuid,
    shift_start: DateTime<Utc>,
}

impl PresenceSource for LateStart {
    fn states(&self, at: DateTime<Utc>) -> Vec<(Uuid, String)> {
        let state = if at < self.shift_start + Duration::minutes(10) {
            "offline"
        } else {
            "available"
        };
        vec![(self.user, state.to_owned())]
    }
}

// feature: G17
// negative: GET /api/v1/workforce/adherence/live
#[test]
fn adherence_percentage_and_peer_forbidden() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let agent = seed_user(app.db(), "wfm-agent").await;
        let peer = seed_user(app.db(), "wfm-peer").await;
        let team = group(&app, &[agent.id]).await;
        let _other = group(&app, &[peer.id]).await;
        grant(&app, peer.id, "wfm_adherence.read").await;

        // Today's shift began an hour ago and runs another hour.
        let now = Utc::now();
        let shift_start = now - Duration::minutes(60);
        let schedule: Uuid = sqlx::query_scalar(
            "INSERT INTO wfm_schedule (id, planning_group_ref, status, is_active, row_version) \
             VALUES (uuidv7(), $1, 'published', true, 0) RETURNING id",
        )
        .bind(team)
        .fetch_one(app.db())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO wfm_shift_assignment (id, schedule_ref, user_ref, start_at, end_at, \
                 activity, is_active, row_version) \
             VALUES (uuidv7(), $1, $2, $3, $4, 'work', true, 0)",
        )
        .bind(schedule)
        .bind(agent.id)
        .bind(shift_start)
        .bind(shift_start + Duration::minutes(120))
        .execute(app.db())
        .await
        .unwrap();

        let source = LateStart {
            user: agent.id,
            shift_start,
        };
        let mut cache = ScheduleCache::default();
        for m in 0..30 {
            record_minute(
                &app.state,
                &mut cache,
                &source,
                shift_start + Duration::minutes(m),
            )
            .await
            .unwrap();
        }
        // The same minute again writes nothing.
        let again = record_minute(&app.state, &mut cache, &source, shift_start)
            .await
            .unwrap();
        assert_eq!(again, 0);

        roll_up_day(app.db(), shift_start.date_naive())
            .await
            .unwrap();
        let pct: f64 = sqlx::query_scalar(
            "SELECT adherence_pct::float8 FROM wfm_adherence_day WHERE user_id = $1 AND day = $2",
        )
        .bind(agent.id)
        .bind(shift_start.date_naive())
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!(pct < 100.0 && pct > 50.0, "{pct}");

        let (status, body) = app
            .request_as(
                &peer.cookie,
                Method::GET,
                &format!("/api/v1/workforce/adherence/live?group={team}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    });
}
