//! D23-T13: the org chart end to end. An account group with six contacts
//! gets its reporting lines through the manager route (one audit event per
//! change), the group chart shows them, a deal's committee map names the
//! missing economic buyer, a manager who leaves lists the reports who need a
//! new manager, and the chart is exported as a PDF render.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

async fn install(app: &TestApp) {
    for pack in ["crm", "sales"] {
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
            let value: Value =
                serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
            attome_api::changeset::boot::apply_pack_document(&app.state, &value)
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        }
    }
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
}

async fn account(app: &TestApp, name: &str, parent: Option<Uuid>) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO account (name, parent_account_ref, is_active, row_version) \
         VALUES ($1, $2, true, 0) RETURNING id",
    )
    .bind(name)
    .bind(parent)
    .fetch_one(app.db())
    .await
    .unwrap()
}

async fn contact(app: &TestApp, name: &str, account: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO contact (full_name, account_ref, is_active, row_version) \
         VALUES ($1, $2, true, 0) RETURNING id",
    )
    .bind(name)
    .bind(account)
    .fetch_one(app.db())
    .await
    .unwrap()
}

async fn if_match(app: &TestApp, contact: Uuid) -> String {
    let version: i64 = sqlx::query_scalar("SELECT row_version FROM contact WHERE id = $1")
        .bind(contact)
        .fetch_one(app.db())
        .await
        .unwrap();
    format!("\"{version}\"")
}

async fn set_manager(app: &TestApp, contact: Uuid, manager: Uuid) {
    let tag = if_match(app, contact).await;
    let (status, body) = app
        .request_with(
            Method::PUT,
            &format!("/api/v1/sales/contacts/{contact}/manager"),
            &[("if-match", tag.as_str())],
            Some(json!({ "manager_id": manager, "line": "solid" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["manager_id"], json!(manager), "{body}");
}

/// The `sales.manager_set` audit events on `contact`, chained or not yet.
async fn manager_events(app: &TestApp, contact: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM audit_header \
                  WHERE record_id = $1 AND event_name = 'sales.manager_set') \
              + (SELECT COUNT(*) FROM audit_ingest \
                  WHERE payload->>'record_id' = $2 \
                    AND payload->>'event_name' = 'sales.manager_set')",
    )
    .bind(contact)
    .bind(contact.to_string())
    .fetch_one(app.db())
    .await
    .unwrap()
}

/// Every node of a chart, depth first, with its manager.
fn walk(nodes: &Value, parent: Option<&str>, out: &mut Vec<(String, Option<String>, Value)>) {
    for node in nodes.as_array().into_iter().flatten() {
        let id = node["id"].as_str().unwrap().to_owned();
        out.push((id.clone(), parent.map(str::to_owned), node.clone()));
        walk(&node["children"], Some(&id), out);
    }
}

// feature: D23
#[test]
fn org_chart_full_flow() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let tag = &Uuid::now_v7().simple().to_string()[..8];
        let holding = account(&app, &format!("Holding {tag}"), None).await;
        let branch = account(&app, &format!("Holding Riyadh {tag}"), Some(holding)).await;

        // Six people across the group.
        let ceo = contact(&app, "Ceo", holding).await;
        let cfo = contact(&app, "Cfo", holding).await;
        let vp = contact(&app, "Vp Sales", branch).await;
        let lead = contact(&app, "Sales Lead", branch).await;
        let rep_a = contact(&app, "Rep A", branch).await;
        let rep_b = contact(&app, "Rep B", branch).await;
        let lines = [
            (cfo, ceo),
            (vp, ceo),
            (lead, vp),
            (rep_a, lead),
            (rep_b, lead),
        ];
        for (person, manager) in lines {
            set_manager(&app, person, manager).await;
        }
        for (person, _) in lines {
            assert_eq!(
                manager_events(&app, person).await,
                1,
                "one audit event for each manager change"
            );
        }

        // The group chart: one root, every line as set, nobody unplaced.
        let all: Vec<String> = [ceo, cfo, vp, lead, rep_a, rep_b]
            .iter()
            .map(Uuid::to_string)
            .collect();
        let chart_path = format!(
            "/api/v1/sales/accounts/{branch}/org-chart?group=true&expand={}",
            all.join(",")
        );
        let (status, chart) = app.request(Method::GET, &chart_path, None).await;
        assert_eq!(status, StatusCode::OK, "{chart}");
        assert_eq!(chart["roots"].as_array().unwrap().len(), 1, "{chart}");
        assert_eq!(chart["roots"][0]["id"], json!(ceo), "{chart}");
        assert!(chart["unplaced"].as_array().unwrap().is_empty(), "{chart}");
        let mut nodes = Vec::new();
        walk(&chart["roots"], None, &mut nodes);
        assert_eq!(nodes.len(), 6, "{chart}");
        for (person, manager) in lines {
            let (_, parent, _) = nodes
                .iter()
                .find(|(id, _, _)| *id == person.to_string())
                .unwrap_or_else(|| panic!("{person} is on the chart: {chart}"));
            assert_eq!(parent.as_deref(), Some(manager.to_string().as_str()));
        }
        let companies: Vec<&Value> = chart["companies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| &c["id"])
            .collect();
        assert!(companies.contains(&&json!(holding)) && companies.contains(&&json!(branch)));

        // A deal at the branch whose stage needs an economic buyer and a
        // champion; only the champion is on it.
        let stage = format!("flow_{tag}");
        sqlx::query(
            "INSERT INTO opportunity_stage (name, stage, required_contact_roles, is_active, \
                 row_version) VALUES ('Flow', $1, '[\"economic_buyer\", \"champion\"]', true, 0)",
        )
        .bind(&stage)
        .execute(app.db())
        .await
        .unwrap();
        let deal: Uuid = sqlx::query_scalar(
            "INSERT INTO opportunity (name, account_ref, stage, owner_ref, is_active, row_version) \
             VALUES ('Flow deal', $1, $2, $3, true, 0) RETURNING id",
        )
        .bind(branch)
        .bind(&stage)
        .bind(app.admin.id)
        .fetch_one(app.db())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO opportunity_contact_role (opportunity_ref, contact_ref, role, \
                 is_active, row_version) VALUES ($1, $2, 'champion', true, 0)",
        )
        .bind(deal)
        .bind(vp)
        .execute(app.db())
        .await
        .unwrap();
        let (status, map) = app
            .request(
                Method::GET,
                &format!("/api/v1/sales/opportunities/{deal}/committee-map"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{map}");
        assert_eq!(map["required_roles"], json!(["economic_buyer", "champion"]));
        let gaps = map["gaps"].as_array().unwrap();
        assert!(
            gaps.iter()
                .any(|g| g["kind"] == "missing_role" && g["role"] == "economic_buyer"),
            "the missing economic buyer is a gap: {map}"
        );
        assert!(
            !gaps.iter().any(|g| g["role"] == "champion"),
            "the champion is covered: {map}"
        );

        // The sales lead leaves: the two reps need a new manager.
        let lead_tag = if_match(&app, lead).await;
        let (status, left) = app
            .request_with(
                Method::POST,
                &format!("/api/v1/sales/contacts/{lead}/left"),
                &[("if-match", lead_tag.as_str())],
                Some(json!({ "left_on": "2026-10-01" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{left}");
        let mut needs: Vec<String> = left["needs_new_manager"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        needs.sort();
        let mut reps = vec![rep_a.to_string(), rep_b.to_string()];
        reps.sort();
        assert_eq!(needs, reps, "{left}");
        let (former, left_on): (Option<bool>, Option<chrono::NaiveDate>) =
            sqlx::query_as("SELECT is_former_employee, left_on::date FROM contact WHERE id = $1")
                .bind(lead)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(former, Some(true));
        assert_eq!(
            left_on.map(|d| d.to_string()).as_deref(),
            Some("2026-10-01")
        );

        // The chart keeps the lead, marked as a former employee.
        let (status, chart) = app.request(Method::GET, &chart_path, None).await;
        assert_eq!(status, StatusCode::OK, "{chart}");
        let mut nodes = Vec::new();
        walk(&chart["roots"], None, &mut nodes);
        let (_, _, node) = nodes
            .iter()
            .find(|(id, _, _)| *id == lead.to_string())
            .unwrap_or_else(|| panic!("the lead stays on the chart: {chart}"));
        assert_eq!(node["is_former_employee"], json!(true), "{node}");

        // The chart exports as a PDF render.
        let (status, export) = app
            .request(
                Method::POST,
                &format!("/api/v1/sales/accounts/{branch}/org-chart/export"),
                Some(json!({ "format": "pdf", "locale": "en" })),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{export}");
        let render = Uuid::parse_str(export["render_id"].as_str().unwrap()).unwrap();
        let (status, body) = app
            .request(
                Method::GET,
                &format!("/api/v1/docgen/renders/{render}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    });
}
