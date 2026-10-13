//! `attome-fleet` — the fleet console (D-792, document/general/FLEET-CONSOLE-DESIGN.md).
//!
//! The developer's view of every customer deployment, inside the CRM but
//! compiled only into a debug `server` built with the non-default
//! `fleet-console` feature, and opened only when every lock of [`gate`]
//! holds. With the gate off nothing here runs: no routes are mounted (a
//! plain 404), no sidebar group is contributed, no job is scheduled, and the
//! fleet key ring is never used.
//!
//! | Module | What |
//! |---|---|
//! | [`gate`] | the four-lock gate and its boot refusals (§2) |
//! | [`core`] | the pure fleet logic moved from `attome-fleet/crates/fleet-core` (§3.2) |
//! | [`client`] | outbound HTTP to a customer, S2S-signed (§5) |
//! | [`crypto`] | rollout secrets at rest (§4.2) |
//! | [`store`] | the `fleet_*` tables, migration 0543 (§4.1) |
//! | [`changesets`] | closed changeset files from `fleet.changesets_dir` (§6.4) |
//! | [`poll`] | F1 sync, F3 notifications, the `FleetPoll` job (§6.1, §6.3) |
//! | [`publish`] | F4 rollouts and the `FleetRolloutStep` job (§6.4) |
//! | [`routes`] | `/api/v1/fleet/**`, loopback-only, `Authorized<Admin>`, session only (§2.5, §6) |
//! | [`sidebar`] | the serve-time Fleet menu group (§7.2) |
//!
//! It is not an `EngineModel` and is never registered with the module registry
//! (that path answers 403 `feature_hidden`, which would name the feature to a
//! customer, and a Module Management switch is a customer admin's switch,
//! D-778). The gated boot path in `crates/server` merges [`router`] as its own
//! route bundle through the one middleware stack (guidelines §3).

pub mod changesets;
pub mod client;
pub mod core;
pub mod crypto;
pub mod error;
pub mod gate;
pub mod poll;
pub mod publish;
pub mod routes;
pub mod runtime;
pub mod sidebar;
pub mod store;

pub use gate::{Gate, GateError, GateInputs};
pub use routes::{openapi, router};
pub use runtime::{FleetRuntime, FleetState};

/// The advisory-lock namespace of every `attome-fleet/…` key (D-351, D-732),
/// registered in `crates/server/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 28;

/// `pg_try_advisory_xact_lock(ADVISORY_LOCK_NAMESPACE, hashtext(key))` in the
/// caller's transaction; `false` when another transaction holds it.
pub(crate) async fn try_lock(
    conn: &mut sqlx::PgConnection,
    key: &str,
) -> Result<bool, attome_types::AppError> {
    sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(ADVISORY_LOCK_NAMESPACE)
        .bind(key)
        .fetch_one(conn)
        .await
        .map_err(attome_types::AppError::internal)
}

/// The console's route bundle when the gate is open, `None` otherwise. The
/// state is built only for an open gate, so a closed one never builds the
/// HTTP client or touches the fleet key.
pub fn mount(
    gate: Gate,
    make_state: impl FnOnce() -> Result<FleetState, attome_types::AppError>,
) -> Result<Option<axum::Router>, attome_types::AppError> {
    if !gate.is_open() {
        return Ok(None);
    }
    Ok(Some(router(make_state()?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    /// Design §2.2 / §2.5: with the gate off the bundle is absent, so the
    /// app answers every documented fleet path with the router's own 404.
    #[tokio::test]
    async fn with_the_gate_off_no_fleet_path_exists() {
        let bundle = mount(Gate::Off, || {
            Err(attome_types::AppError::internal(
                "the state must not be built for a closed gate",
            ))
        })
        .expect("a closed gate never fails");
        assert!(bundle.is_none());

        let app = axum::Router::new().merge(bundle.unwrap_or_else(axum::Router::new));
        let document = serde_json::to_value(openapi()).expect("serializes");
        let paths = document["paths"].as_object().expect("paths");
        assert!(
            paths.len() >= 15,
            "the fragment documents the console's routes"
        );
        for (path, operations) in paths {
            let concrete = path
                .replace("{id}", "0190f6f2-0000-7000-8000-000000000001")
                .replace("{target_id}", "0190f6f2-0000-7000-8000-000000000002")
                .replace("{report_id}", "0190f6f2-0000-7000-8000-000000000003")
                .replace("{item_id}", "0190f6f2-0000-7000-8000-000000000004");
            for method in operations.as_object().expect("operations").keys() {
                let request = Request::builder()
                    .method(method.to_ascii_uppercase().as_str())
                    .uri(&concrete)
                    .body(Body::empty())
                    .expect("request");
                let response = app.clone().oneshot(request).await.expect("answers");
                assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
            }
        }
    }

    #[test]
    fn every_documented_path_is_under_the_fleet_prefix() {
        let document = serde_json::to_value(openapi()).expect("serializes");
        for path in document["paths"].as_object().expect("paths").keys() {
            assert!(path.starts_with("/api/v1/fleet/"), "{path}");
        }
    }
}
