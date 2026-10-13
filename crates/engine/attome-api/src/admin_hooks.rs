//! Solution 7 Phase 1 (D-785, design §1 and §4) — the small helpers the UI
//! metadata admin files (views, sidebar, apps, calendars, rules) share to
//! hook their writes into the changeset recorder. Each is a thin adapter over
//! `attome_core::changeset`, which owns the rules. (They lived in
//! `form_admin.rs` until the form-metadata routes were removed, D-790.)

use attome_core::changeset::{Layer, Op, RecordedOp, Recording};
use attome_metadata::provision::ReconcilePolicy;
use attome_types::AppError;
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

/// Parses an `owner_layer` column value. The column has a CHECK
/// constraint (migration 0520), so anything else is a defect.
pub(crate) fn parse_layer(value: &str) -> Result<Layer, AppError> {
    Layer::parse(value)
        .ok_or_else(|| AppError::internal(format!("unknown owner_layer {value:?} on a row")))
}

/// 409 `layer_mismatch` unless `recording` may update, retire or remove
/// a row whose `owner_layer` is `row_layer`.
pub(crate) fn check_row_owner(recording: &Recording, row_layer: &str) -> Result<(), AppError> {
    recording.check_owner(parse_layer(row_layer)?)
}

/// The layer a bundle/seed reconcile stamps on a row it inserts (design
/// §1.4, §2.2 step 3): boot seeds own the platform definitions; bundle
/// import (and an admin-policy reconcile) writes `project`.
pub(crate) fn reconcile_layer(policy: ReconcilePolicy) -> Layer {
    match policy {
        ReconcilePolicy::Seed => Layer::Platform,
        ReconcilePolicy::Admin | ReconcilePolicy::Bundle { .. } => Layer::Project,
    }
}

/// One recorded op whose snapshot is the post-write row `row` (the same
/// enumerated columns the route returns).
pub(crate) fn recorded(
    op: Op,
    object_kind: &'static str,
    object_ref: Uuid,
    target: Value,
    row: &impl Serialize,
) -> Result<RecordedOp, AppError> {
    Ok(RecordedOp {
        op,
        object_kind,
        object_ref: Some(object_ref),
        target,
        snapshot: serde_json::to_value(row).map_err(AppError::internal)?,
        changed: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn seeds_stamp_platform_and_everything_else_project() {
        assert_eq!(reconcile_layer(ReconcilePolicy::Seed), Layer::Platform);
        assert_eq!(reconcile_layer(ReconcilePolicy::Admin), Layer::Project);
        assert_eq!(
            reconcile_layer(ReconcilePolicy::Bundle {
                is_customized: true
            }),
            Layer::Project
        );
    }

    #[test]
    fn an_unknown_layer_is_an_internal_error_not_a_pass() {
        assert_eq!(parse_layer("project").ok(), Some(Layer::Project));
        assert!(matches!(parse_layer("vendor"), Err(AppError::Internal(_))));
        assert!(matches!(
            check_row_owner(&Recording::Seed, "vendor"),
            Err(AppError::Internal(_))
        ));
    }

    #[test]
    fn the_owner_rule_follows_the_recording_layer() {
        let applying = Recording::Applying {
            layer: Layer::Project,
        };
        assert!(check_row_owner(&applying, "project").is_ok());
        let Err(AppError::Conflict(message)) = check_row_owner(&applying, "platform") else {
            panic!("a platform row must be refused to a project recording");
        };
        assert_eq!(
            attome_core::changeset::errors::code_of(message),
            "layer_mismatch"
        );
    }

    #[test]
    fn a_recorded_op_carries_the_row_as_its_snapshot() {
        #[derive(Serialize)]
        struct Row {
            name: &'static str,
            owner_layer: &'static str,
        }
        let id = Uuid::now_v7();
        let op = recorded(
            Op::UpsertApp,
            "app",
            id,
            json!({ "app": "sales" }),
            &Row {
                name: "sales",
                owner_layer: "project",
            },
        )
        .expect("op");
        assert_eq!(op.object_ref, Some(id));
        assert_eq!(
            op.snapshot,
            json!({ "name": "sales", "owner_layer": "project" })
        );
        assert!(op.check().is_ok());
    }
}
