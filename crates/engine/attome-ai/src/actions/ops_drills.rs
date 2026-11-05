//! AB4-T12: an operations agent reads how fresh the recovery drills are and
//! one drill's evidence, to explain a failure. Reads only: no tool uploads,
//! edits or marks evidence (the evidence route takes a drill host's signed
//! report, never an agent's).
//!
//! - `ops.drill_freshness` (Read, `ops.read`) — every drill kind's status
//!   (`fresh`, `stale`, `failed`, `never`), when it last ran and passed,
//!   and the checks it failed.
//! - `ops.drill_evidence` (Read, `ops.read`) — one drill's numbers (RPO,
//!   RTO, data size, the overall result) and its checks' names and results;
//!   the free-text check details are left out.
//! - `ops.chaos_results` (Read, `ops.read`, AB9-T9) — the latest chaos
//!   drills: when each ran, the fault it injected and whether it passed.
//!   No tool asks for or starts a chaos run: a production game day is a
//!   person's request, approved by a second person (AB9-T7).

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_OPS;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const OPS_DRILL_FRESHNESS: &str = "ops.drill_freshness";
pub const OPS_DRILL_EVIDENCE: &str = "ops.drill_evidence";
pub const OPS_CHAOS_RESULTS: &str = "ops.chaos_results";

/// Most chaos drills one read answers.
pub const MAX_CHAOS_RESULTS: i64 = 50;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            OPS_DRILL_FRESHNESS,
            "Read how fresh each kind of recovery drill is (restore, failover, chaos, upgrade, \
             secrets, recovery, drain): fresh, stale, failed or never, when it last ran and \
             passed, the allowed period and the checks the last run failed.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_OPS,
            &["ops.read"],
        )
        .input_schema(r#"{"type": "object", "properties": {}, "additionalProperties": false}"#),
        ActionDescriptor::new(
            OPS_DRILL_EVIDENCE,
            "Read one recovery drill's evidence by its id: the kind, when it ran, whether it \
             passed, the recovery point and time in seconds, the data size, and each check's \
             name and result.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_OPS,
            &["ops.read"],
        )
        .input_schema(
            r#"{"type": "object", "required": ["drill_id"], "properties": {"drill_id": {"type": "string", "format": "uuid"}}, "additionalProperties": false}"#,
        ),
        ActionDescriptor::new(
            OPS_CHAOS_RESULTS,
            "Read the latest chaos (fault injection) drills, newest first: each one's id, when it \
             finished, the fault it injected and whether it passed, with how many passed and \
             failed. Reads only; a chaos run is never started from here.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_OPS,
            &["ops.read"],
        )
        .input_schema(
            r#"{"type": "object", "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 50}}, "additionalProperties": false}"#,
        ),
    ]
}

pub fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(OpsDrillFreshness),
        Box::new(OpsDrillEvidence),
        Box::new(OpsChaosResults),
    ]
}

/// The numbers and check results of one signed report; no free text. Pure.
pub fn summary(id: Uuid, signed: &attome_ops::evidence::SignedEvidence) -> Value {
    let e = &signed.evidence;
    json!({
        "drill_id": id,
        "kind": attome_ops::drills::kind_name(e.kind),
        "started_at": e.started_at,
        "finished_at": e.finished_at,
        "overall_ok": e.overall_ok,
        "restore_ok": e.restore_ok,
        "provenance_ok": e.provenance_ok,
        "rpo_seconds": e.rpo_seconds,
        "rto_seconds": e.rto_seconds,
        "data_size_bytes": e.data_size_bytes,
        "platform_version": e.platform_version,
        "checks": e.checks.iter().map(|c| json!({ "name": c.name, "result": c.result })).collect::<Vec<_>>(),
    })
}

pub(crate) struct OpsDrillFreshness;

impl Action for OpsDrillFreshness {
    fn id(&self) -> ActionId {
        ActionId(OPS_DRILL_FRESHNESS)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        _ctx: &'a ActionContext,
        _args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let kinds = attome_ops::freshness::all(&state.base.db).await?;
            Ok(ActionResult::plain(json!({
                "kinds": serde_json::to_value(kinds).map_err(AppError::internal)?,
            })))
        })
    }
}

pub(crate) struct OpsDrillEvidence;

impl Action for OpsDrillEvidence {
    fn id(&self) -> ActionId {
        ActionId(OPS_DRILL_EVIDENCE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        _ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let id = args["drill_id"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or_else(|| AppError::Validation("drill_id is a drill id".into()))?;
            let signed = attome_ops::drills::drill_evidence(&state.base.db, id)
                .await?
                .ok_or(AppError::NotFound)?;
            Ok(ActionResult::plain(summary(id, &signed)))
        })
    }
}

/// The chaos results an agent reads: each drill's id, finish, fault and
/// result, and the counts. Pure.
pub fn chaos_results(runs: &[attome_ops::drills::DrillRun]) -> Value {
    let passed = runs.iter().filter(|r| r.overall_ok).count();
    json!({
        "drills": runs
            .iter()
            .map(|r| json!({
                "drill_id": r.id,
                "finished_at": r.finished_at,
                "fault": r.fault,
                "overall_ok": r.overall_ok,
            }))
            .collect::<Vec<_>>(),
        "passed": passed,
        "failed": runs.len() - passed,
    })
}

pub(crate) struct OpsChaosResults;

impl Action for OpsChaosResults {
    fn id(&self) -> ActionId {
        ActionId(OPS_CHAOS_RESULTS)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        _ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let limit = match args.get("limit") {
                None | Some(Value::Null) => 10,
                Some(v) => v
                    .as_i64()
                    .filter(|n| (1..=MAX_CHAOS_RESULTS).contains(n))
                    .ok_or_else(|| {
                        AppError::Validation(format!("limit is 1 to {MAX_CHAOS_RESULTS}"))
                    })?,
            };
            let runs = attome_ops::drills::recent_runs(
                &state.base.db,
                Some(attome_ops::evidence::EvidenceKind::Chaos),
                limit,
            )
            .await?;
            Ok(ActionResult::plain(chaos_results(&runs)))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drill_tools_are_read_tier() {
        for d in descriptors() {
            assert_eq!(d.risk, RiskTier::Read, "{}", d.id.0);
            assert_eq!(d.effect, Effect::Read, "{}", d.id.0);
            assert_eq!(d.required_privileges, &["ops.read"]);
        }
    }

    #[test]
    fn no_ops_write_tool_for_evidence() {
        let writes: Vec<&str> = crate::actions::all()
            .into_iter()
            .filter(|d| d.id.0.starts_with("ops.drill") && d.risk != RiskTier::Read)
            .map(|d| d.id.0)
            .collect();
        assert!(writes.is_empty(), "{writes:?}");
    }

    /// AB9-T9: no action can ask for or start a chaos run: every action
    /// naming chaos only reads.
    #[test]
    fn no_production_chaos_tool() {
        let chaos: Vec<_> = crate::actions::all()
            .into_iter()
            .filter(|d| d.id.0.contains("chaos"))
            .collect();
        assert!(
            chaos.iter().any(|d| d.id.0 == OPS_CHAOS_RESULTS),
            "the chaos read is registered"
        );
        for d in chaos {
            assert_eq!(d.risk, RiskTier::Read, "{} only reads", d.id.0);
            assert_eq!(d.effect, Effect::Read, "{} only reads", d.id.0);
        }
    }

    #[test]
    fn chaos_results_count_passed_and_failed() {
        let at = chrono::Utc::now();
        let run = |ok: bool, fault: &str| attome_ops::drills::DrillRun {
            id: Uuid::now_v7(),
            kind: "chaos".into(),
            started_at: at,
            finished_at: at,
            overall_ok: ok,
            restore_ok: true,
            provenance_ok: true,
            rpo_seconds: None,
            rto_seconds: None,
            data_size_bytes: None,
            platform_version: "2.0.0".into(),
            key_id: "k".into(),
            sha256: "s".into(),
            uploaded_by: None,
            created_at: at,
            fault: Some(fault.into()),
        };
        let out = chaos_results(&[run(true, "redis-down"), run(false, "process-kill")]);
        assert_eq!(out["passed"], 1);
        assert_eq!(out["failed"], 1);
        assert_eq!(out["drills"][1]["fault"], "process-kill");
    }

    #[test]
    fn the_summary_carries_numbers_and_results_only() {
        use attome_ops::evidence::{Check, CheckResult, Evidence, EvidenceKind, SigningKey};
        let at = chrono::Utc::now();
        let mut e = Evidence {
            schema: attome_ops::evidence::SCHEMA.into(),
            kind: EvidenceKind::Restore,
            drill_id: Uuid::nil(),
            started_at: at,
            finished_at: at,
            platform_version: "2.0.0".into(),
            image_digest: None,
            deployment_id: None,
            checks: vec![Check {
                name: "sample_api_reads".into(),
                result: CheckResult::Fail,
                detail: Some("GET /api/v1/contact answered 500".into()),
            }],
            rpo_seconds: Some(90.0),
            rto_seconds: Some(300.0),
            data_size_bytes: Some(1 << 20),
            restore_ok: true,
            provenance_ok: true,
            overall_ok: true,
            extra: serde_json::Map::new(),
        };
        e.compute_overall();
        let signed = attome_ops::evidence::sign(&e, &SigningKey::from_bytes(&[1; 32])).unwrap();
        let out = summary(Uuid::nil(), &signed);
        assert_eq!(out["kind"], json!("restore"));
        assert_eq!(out["overall_ok"], json!(false));
        assert_eq!(
            out["checks"],
            json!([{ "name": "sample_api_reads", "result": "fail" }])
        );
        assert!(!out.to_string().contains("answered 500"));
    }
}
