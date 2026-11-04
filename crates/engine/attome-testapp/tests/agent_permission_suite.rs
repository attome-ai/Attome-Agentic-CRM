//! AH7-T6: every seeded agent passes its permission test, and an over-wide
//! policy is not a failure: the gate still refuses, for the agent, every
//! call its owner may not make.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use uuid::Uuid;

/// The AI definitions and seeded agents the server's boot applies, in its
/// order.
async fn definitions(app: &TestApp) {
    for name in [
        "attome-ai-tone",
        "xrm-core-authentication-type",
        "xrm-core-authentication-type-data",
        "attome-ai-provider",
        "attome-ai-provider-data",
        "attome-ai-model-catalog",
        "attome-ai-model-catalog-data",
        "attome-ai-agent",
        "attome-ai-agent-principal",
        "attome-ai-capability-pack",
        "attome-ai-agent-data",
        "attome-ai-service-agent",
        "attome-ai-lead-agent",
        "attome-ai-inbox-agent",
        "attome-ai-ops-agent",
    ] {
        attome_api::changeset::boot::apply_platform_definition(&app.state, name)
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    let registry = attome_core::build_registry(&app.state.base.db)
        .await
        .expect("build the metadata registry");
    app.state.entities.swap(registry);
}

// feature: AH7
#[test]
fn every_seeded_agent_passes_permission_test() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        definitions(&app).await;
        let agents: Vec<(String, Uuid)> = sqlx::query_as(
            "SELECT name, policy_ref FROM ai_agent \
              WHERE policy_ref IS NOT NULL AND is_active IS DISTINCT FROM false",
        )
        .fetch_all(app.db())
        .await
        .unwrap();
        assert!(agents.len() >= 4, "the four seeded agents: {agents:?}");
        for (name, policy) in agents {
            let judged =
                attome_ai::agent_activation::judge_policy(&app.state, app.admin.id, policy, None)
                    .await
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(
                judged.failures.is_empty(),
                "{name} fails its permission test: {:?}",
                judged.failures
            );
            assert!(judged.cases > 0, "{name} has no cases");
        }
    });
}

// feature: AH7
#[test]
fn over_wide_policy_is_refused_by_the_gate_not_failed() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        definitions(&app).await;
        // Every action allowed, up to consequential, for an owner with no
        // privileges at all.
        let policy = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO ai_agent_policy \
                (id, name, risk_ceiling, max_invocations_per_session, max_writes_per_day, \
                 max_tokens_per_session, max_session_duration_minutes, created_at) \
             VALUES ($1, 'everything', 'consequential', 100, 100, 20000, 60, NOW())",
        )
        .bind(policy)
        .execute(app.db())
        .await
        .unwrap();
        let owner = attome_testapp::seed_user(app.db(), "no-privileges").await;
        // The owner must read the policy to be judged under it.
        sqlx::query("UPDATE ai_agent_policy SET owner_ref = $2 WHERE id = $1")
            .bind(policy)
            .bind(owner.id)
            .execute(app.db())
            .await
            .unwrap();
        match attome_ai::agent_activation::judge_policy(&app.state, owner.id, policy, None).await {
            Ok(judged) => {
                assert!(judged.failures.is_empty(), "{:?}", judged.failures);
                assert!(
                    !judged.summary.cannot_do.is_empty(),
                    "the gate refuses what the owner may not do"
                );
            }
            // An owner who cannot even read agent policies is refused the
            // activation outright, which is stricter still.
            Err(attome_types::AppError::Validation(message)) => {
                assert!(message.contains("cannot read its policy"), "{message}");
            }
            Err(e) => panic!("{e}"),
        }
    });
}
