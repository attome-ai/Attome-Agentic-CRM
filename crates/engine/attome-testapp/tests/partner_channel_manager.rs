//! F9-T8: the internal Channel Manager role reads and decides only the
//! registrations and MDF of the partners whose `partner_manager_ref` is the
//! caller (`partner_account_ref.partner_manager_ref eq @me`), and an MDF
//! request or claim carries its fund's partner whatever the writer sends.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::{TestApp, TestUser};
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

const ROLE: &str = "Channel Manager";

fn packs_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packs")
}

async fn install(app: &TestApp, pack: &str) -> Result<(), String> {
    let dir = packs_dir().join(pack).join("changesets");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    for file in &files {
        let value: Value = serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
        attome_api::changeset::boot::apply_pack_document(&app.state, &value)
            .await
            .map_err(|e| format!("{}: {e}", file.display()))?;
    }
    Ok(())
}

/// The packs the partner pack's lookups need, in whatever order they install.
async fn install_partner(app: &TestApp) {
    let mut left = vec![
        "crm",
        "sales",
        "vendor-supplier",
        "contract-management",
        "partner",
    ];
    let mut last = Vec::new();
    for _ in 0..5 {
        let mut failed = Vec::new();
        for pack in left {
            if let Err(error) = install(app, pack).await {
                failed.push((pack, error));
            }
        }
        if failed.is_empty() {
            let registry = attome_core::build_registry(app.db()).await.unwrap();
            app.state.entities.swap(registry);
            return;
        }
        left = failed.iter().map(|(pack, _)| *pack).collect();
        if left.len() == 5 {
            panic!("no pack installs: {failed:?}");
        }
        last = failed;
    }
    panic!("packs left uninstalled: {last:?}");
}

async fn create(app: &TestApp, entity: &str, body: Value) -> Uuid {
    let (status, out) = app
        .request(Method::POST, &format!("/api/v1/{entity}"), Some(body))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{entity}: {out}");
    out["id"].as_str().unwrap().parse().unwrap()
}

async fn partner_of(app: &TestApp, table: &str, id: Uuid) -> Option<Uuid> {
    sqlx::query_scalar(&format!(
        "SELECT partner_account_ref FROM {} WHERE id = $1",
        attome_core::quote_ident(table)
    ))
    .bind(id)
    .fetch_one(app.db())
    .await
    .unwrap()
}

async fn channel_manager(app: &TestApp, label: &str) -> TestUser {
    let user =
        attome_testapp::seed_user(app.db(), &format!("{label}-{}", Uuid::now_v7().simple())).await;
    let role: Uuid =
        sqlx::query_scalar("SELECT id FROM role WHERE name = $1 AND is_deleted = false")
            .bind(ROLE)
            .fetch_one(app.db())
            .await
            .unwrap_or_else(|e| panic!("role {ROLE}: {e}"));
    sqlx::query("INSERT INTO user_account_mm_role (user_ref, role_ref) VALUES ($1, $2)")
        .bind(user.id)
        .bind(role)
        .execute(app.db())
        .await
        .expect("grant role");
    user
}

struct World {
    mine: Uuid,
    theirs: Uuid,
    me: TestUser,
}

/// Two partners, each managed by its own channel manager; `me` manages
/// `mine`.
async fn world(app: &TestApp) -> World {
    let me = channel_manager(app, "cm-me").await;
    let other = channel_manager(app, "cm-other").await;
    let suffix = Uuid::now_v7().simple().to_string();
    let partner = |name: String, manager: Uuid| {
        create(
            app,
            "account",
            json!({ "name": name, "is_partner": true, "partner_manager_ref": manager }),
        )
    };
    World {
        mine: partner(format!("Managed partner {suffix}"), me.id).await,
        theirs: partner(format!("Other partner {suffix}"), other.id).await,
        me,
    }
}

/// The response as text: a listed record's id appears in it.
fn ids(body: &Value) -> String {
    body.to_string()
}

// feature: F9
#[test]
fn channel_manager_reads_only_managed_partners() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install_partner(&app).await;
        let w = world(&app).await;
        let customer = create(
            &app,
            "account",
            json!({ "name": format!("Customer {}", Uuid::now_v7().simple()) }),
        )
        .await;
        let registration = |partner: Uuid| {
            let app = &app;
            async move {
                create(
                    app,
                    "deal_registration",
                    json!({
                        "partner_account_ref": partner,
                        "customer_account_ref": customer,
                        "customer_name": format!("Deal {}", Uuid::now_v7().simple()),
                    }),
                )
                .await
            }
        };
        let mine = registration(w.mine).await;
        let theirs = registration(w.theirs).await;

        let (status, body) = app
            .request_as(&w.me.cookie, Method::GET, "/api/v1/deal_registration", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let listed = ids(&body);
        assert!(listed.contains(&mine.to_string()), "{body}");
        assert!(!listed.contains(&theirs.to_string()), "{body}");

        let (status, body) = app
            .request_as(
                &w.me.cookie,
                Method::GET,
                &format!("/api/v1/deal_registration/{theirs}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

        let (status, body) = app
            .request_as(&w.me.cookie, Method::GET, "/api/v1/account", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let listed = ids(&body);
        assert!(listed.contains(&w.mine.to_string()), "{body}");
        assert!(!listed.contains(&w.theirs.to_string()), "{body}");
        assert!(!listed.contains(&customer.to_string()), "{body}");
    });
}

// feature: F9
#[test]
fn mdf_partner_comes_from_the_fund() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install_partner(&app).await;
        let w = world(&app).await;
        let fund = create(
            &app,
            "mdf_fund",
            json!({ "partner_account_ref": w.mine, "fiscal_year": "2027", "amount": 1000 }),
        )
        .await;
        // The writer names the other partner; the rule puts the fund's back.
        let request = create(
            &app,
            "mdf_request",
            json!({
                "fund_ref": fund,
                "partner_account_ref": w.theirs,
                "activity": "Webinar",
                "amount": 100,
                "status": "submitted",
            }),
        )
        .await;
        assert_eq!(partner_of(&app, "mdf_request", request).await, Some(w.mine));
        let claim = create(
            &app,
            "mdf_claim",
            json!({ "request_ref": request, "partner_account_ref": w.theirs, "amount": 50 }),
        )
        .await;
        assert_eq!(partner_of(&app, "mdf_claim", claim).await, Some(w.mine));
    });
}

// feature: F9
// negative: POST /api/v1/partner/mdf/requests/{id}/decision
#[test]
fn channel_manager_decides_only_managed_mdf() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install_partner(&app).await;
        let w = world(&app).await;
        let request = |partner: Uuid| {
            let app = &app;
            async move {
                let fund = create(
                    app,
                    "mdf_fund",
                    json!({ "partner_account_ref": partner, "fiscal_year": "2027", "amount": 1000 }),
                )
                .await;
                create(
                    app,
                    "mdf_request",
                    json!({ "fund_ref": fund, "activity": "Event", "amount": 200, "status": "submitted" }),
                )
                .await
            }
        };
        let mine = request(w.mine).await;
        let theirs = request(w.theirs).await;
        let decide = |id: Uuid| {
            let app = &app;
            let cookie = w.me.cookie.clone();
            async move {
                app.request_as(
                    &cookie,
                    Method::POST,
                    &format!("/api/v1/partner/mdf/requests/{id}/decision"),
                    Some(json!({ "decision": "approve" })),
                )
                .await
            }
        };

        let (status, body) = decide(theirs).await;
        assert!(
            matches!(status, StatusCode::NOT_FOUND | StatusCode::FORBIDDEN),
            "{status}: {body}"
        );
        let (status, body) = decide(mine).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let (status, body) = app
            .request_as(&w.me.cookie, Method::GET, "/api/v1/mdf_request", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let listed = ids(&body);
        assert!(listed.contains(&mine.to_string()), "{body}");
        assert!(!listed.contains(&theirs.to_string()), "{body}");
    });
}
