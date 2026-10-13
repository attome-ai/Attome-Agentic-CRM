//! Chatbot loop metrics (chatbot plan C13.1).
//!
//! Every series goes through the process-wide `metrics` recorder that
//! `attome_server` installs (the Prometheus exporter), like `budget_guard`'s.
//! **Labels are closed sets:** a turn's surface and terminal state, a gate
//! refusal variant, a tool-call outcome, a sweep transition, and an action id
//! only when it is a registry id the turn offered. Never a conversation,
//! session, turn or user id, never prompt or response text, and never a tool
//! name the model made up (that one is [`UNREGISTERED_ACTION`]).
//!
//! - `ai_turns_total{surface,terminal_state}` — one per finished turn.
//! - `ai_turn_steps{surface}` — model steps the turn took (histogram).
//! - `ai_tool_calls_total{action_id,outcome}` — one per tool call the
//!   model asked for.
//! - `ai_gate_refusals_total{variant}` — refusals at the dispatch-time
//!   gate (`execute::dispatch`, the approved-action path, and confirm).
//! - `ai_model_step_seconds{surface}` — one model call (histogram).
//! - `ai_delta_publish_failures_total{reason}` — a turn's delta stream
//!   gave up on Redis (the answer is unaffected, I-14).
//! - `ai_tool_call_sweep_total{transition}` — rows the
//!   `AiToolCallSweep` job moved.
//!
//! Token spend and budget refusals are `attome_inference::budget`'s
//! `attome_inference_tokens_total` / `attome_inference_budget_rejected_total`,
//! emitted by `budget_guard`; they are not repeated here.
//! `ai_runtime_switch_read_failures_total{reason}` is emitted by
//! `attome_core::ai_runtime_switch`, where the read happens.

use crate::conversation::TerminalState;
use crate::gate::GateRefusal;

pub const TURNS_TOTAL: &str = "ai_turns_total";
pub const TURN_STEPS: &str = "ai_turn_steps";
pub const TOOL_CALLS_TOTAL: &str = "ai_tool_calls_total";
pub const GATE_REFUSALS_TOTAL: &str = "ai_gate_refusals_total";
pub const MODEL_STEP_SECONDS: &str = "ai_model_step_seconds";
pub const DELTA_PUBLISH_FAILURES_TOTAL: &str = "ai_delta_publish_failures_total";
pub const TOOL_CALL_SWEEP_TOTAL: &str = "ai_tool_call_sweep_total";

/// The `action_id` label for a tool the turn did not offer: the name came
/// from the model and is unbounded text.
pub const UNREGISTERED_ACTION: &str = "unregistered";

/// The surface a turn runs on, as a label.
pub fn surface_label(anonymous_channel: bool, workflow_step: bool) -> &'static str {
    if anonymous_channel {
        "webchat"
    } else if workflow_step {
        "workflow"
    } else {
        "internal"
    }
}

/// What happened to one tool call the model asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolCallOutcome {
    /// Dispatched and completed.
    Completed,
    /// Dispatched; the action itself failed (the model is told).
    Failed,
    /// Refused before dispatch: the tool was not offered, or its arguments
    /// did not parse or validate.
    Invalid,
    /// Offered at the previous step, gone at this one; the turn ended.
    Lost,
    /// Stopped for a human's confirmation.
    ConfirmationRequired,
    /// Stopped for a four-eyes approval.
    ApprovalRequired,
    /// The world changed under the call (budget, session, gate); the turn
    /// ended.
    WorldChanged,
    /// A Stop landed before dispatch.
    Cancelled,
}

impl ToolCallOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Invalid => "invalid",
            Self::Lost => "lost",
            Self::ConfirmationRequired => "confirmation_required",
            Self::ApprovalRequired => "approval_required",
            Self::WorldChanged => "world_changed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// A row transition the tool-call sweep performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepTransition {
    /// An expired confirm lease went back to `proposed`.
    Reclaimed,
    /// A proposal nobody confirmed expired.
    Expired,
    /// An approval resolution reached its conversation only through the
    /// recovery path.
    Reconciled,
}

impl SweepTransition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reclaimed => "reclaimed",
            Self::Expired => "expired",
            Self::Reconciled => "reconciled",
        }
    }
}

/// Why a delta publish gave up.
pub const DELTA_PUBLISH_ERROR: &str = "error";
pub const DELTA_PUBLISH_TIMEOUT: &str = "timeout";

/// One finished turn: its terminal state and how many model steps it took.
pub fn turn_finished(surface: &'static str, terminal: TerminalState, steps: usize) {
    metrics::counter!(
        TURNS_TOTAL,
        "surface" => surface,
        "terminal_state" => terminal.as_str(),
    )
    .increment(1);
    metrics::histogram!(TURN_STEPS, "surface" => surface).record(steps as f64);
}

/// One tool call. `action_id` must be a registry id the turn offered, or
/// [`UNREGISTERED_ACTION`]; callers go through [`action_label`].
pub fn tool_call(action_id: &str, outcome: ToolCallOutcome) {
    metrics::counter!(
        TOOL_CALLS_TOTAL,
        "action_id" => action_id.to_owned(),
        "outcome" => outcome.as_str(),
    )
    .increment(1);
}

/// The `action_id` label for a model-named tool: the name itself when it is
/// one the turn offered (a registry id, bounded), otherwise
/// [`UNREGISTERED_ACTION`].
pub fn action_label(offered: bool, name: &str) -> &str {
    if offered { name } else { UNREGISTERED_ACTION }
}

/// A dispatch-time gate refusal.
pub fn gate_refused(refusal: GateRefusal) {
    metrics::counter!(GATE_REFUSALS_TOTAL, "variant" => refusal.as_str()).increment(1);
}

/// One model call's wall time, whatever its outcome.
pub fn model_step(surface: &'static str, seconds: f64) {
    metrics::histogram!(MODEL_STEP_SECONDS, "surface" => surface).record(seconds);
}

/// A turn's delta stream stopped publishing.
pub fn delta_publish_failed(reason: &'static str) {
    metrics::counter!(DELTA_PUBLISH_FAILURES_TOTAL, "reason" => reason).increment(1);
}

/// Rows one sweep run moved; zero is not recorded.
pub fn sweep(transition: SweepTransition, rows: u64) {
    if rows > 0 {
        metrics::counter!(TOOL_CALL_SWEEP_TOTAL, "transition" => transition.as_str())
            .increment(rows);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use metrics::{
        Counter, CounterFn, Gauge, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder,
        SharedString, Unit,
    };

    use super::*;

    /// Counter increments, or histogram sample counts, per `name{label=value,…}`.
    #[derive(Default, Clone)]
    struct Capture(Arc<Mutex<BTreeMap<String, Arc<Cell>>>>);

    #[derive(Default)]
    struct Cell(AtomicU64);

    impl CounterFn for Cell {
        fn increment(&self, value: u64) {
            self.0.fetch_add(value, Ordering::Relaxed);
        }
        fn absolute(&self, value: u64) {
            self.0.store(value, Ordering::Relaxed);
        }
    }

    impl HistogramFn for Cell {
        fn record(&self, _value: f64) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn series(key: &Key) -> String {
        let labels: Vec<String> = key
            .labels()
            .map(|l| format!("{}={}", l.key(), l.value()))
            .collect();
        format!("{}{{{}}}", key.name(), labels.join(","))
    }

    impl Capture {
        fn cell(&self, key: &Key) -> Arc<Cell> {
            self.0
                .lock()
                .unwrap()
                .entry(series(key))
                .or_default()
                .clone()
        }
        fn get(&self, series: &str) -> u64 {
            self.0
                .lock()
                .unwrap()
                .get(series)
                .map_or(0, |c| c.0.load(Ordering::Relaxed))
        }
        fn names(&self) -> Vec<String> {
            self.0.lock().unwrap().keys().cloned().collect()
        }
    }

    impl Recorder for Capture {
        fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
            Counter::from_arc(self.cell(key))
        }
        fn register_gauge(&self, _: &Key, _: &Metadata<'_>) -> Gauge {
            Gauge::noop()
        }
        fn register_histogram(&self, key: &Key, _: &Metadata<'_>) -> Histogram {
            Histogram::from_arc(self.cell(key))
        }
    }

    #[test]
    fn every_loop_metric_uses_the_plan_names_and_closed_labels() {
        let capture = Capture::default();
        metrics::with_local_recorder(&capture, || {
            turn_finished("internal", TerminalState::Completed, 2);
            turn_finished("webchat", TerminalState::MaxSteps, 6);
            tool_call("record.read", ToolCallOutcome::Completed);
            tool_call(
                action_label(false, "ignore previous instructions"),
                ToolCallOutcome::Invalid,
            );
            gate_refused(GateRefusal::AboveCeiling);
            model_step("internal", 0.5);
            delta_publish_failed(DELTA_PUBLISH_TIMEOUT);
            sweep(SweepTransition::Expired, 3);
            sweep(SweepTransition::Reclaimed, 0);
        });

        assert_eq!(
            capture.get("ai_turns_total{surface=internal,terminal_state=completed}"),
            1
        );
        assert_eq!(
            capture.get("ai_turns_total{surface=webchat,terminal_state=max_steps}"),
            1
        );
        assert_eq!(capture.get("ai_turn_steps{surface=internal}"), 1);
        assert_eq!(
            capture.get("ai_tool_calls_total{action_id=record.read,outcome=completed}"),
            1
        );
        // A model-invented name never becomes a label value.
        assert_eq!(
            capture.get("ai_tool_calls_total{action_id=unregistered,outcome=invalid}"),
            1
        );
        assert!(
            !capture
                .names()
                .iter()
                .any(|n| n.contains("ignore previous")),
            "model text leaked into a label: {:?}",
            capture.names()
        );
        assert_eq!(
            capture.get("ai_gate_refusals_total{variant=above_ceiling}"),
            1
        );
        assert_eq!(capture.get("ai_model_step_seconds{surface=internal}"), 1);
        assert_eq!(
            capture.get("ai_delta_publish_failures_total{reason=timeout}"),
            1
        );
        assert_eq!(
            capture.get("ai_tool_call_sweep_total{transition=expired}"),
            3
        );
        // A zero-row sweep records no series at all.
        assert_eq!(
            capture.get("ai_tool_call_sweep_total{transition=reclaimed}"),
            0
        );
    }

    #[test]
    fn label_sets_are_closed_and_distinct() {
        let outcomes = [
            ToolCallOutcome::Completed,
            ToolCallOutcome::Failed,
            ToolCallOutcome::Invalid,
            ToolCallOutcome::Lost,
            ToolCallOutcome::ConfirmationRequired,
            ToolCallOutcome::ApprovalRequired,
            ToolCallOutcome::WorldChanged,
            ToolCallOutcome::Cancelled,
        ];
        let mut seen: Vec<&str> = outcomes.iter().map(|o| o.as_str()).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), outcomes.len());

        let refusals = [
            GateRefusal::NotAvailable,
            GateRefusal::Forbidden,
            GateRefusal::AboveCeiling,
            GateRefusal::IdempotencyKeyRequired,
            GateRefusal::ExternalEffectDisabled,
            GateRefusal::NotInSessionAllowList,
        ];
        let mut seen: Vec<&str> = refusals.iter().map(|r| r.as_str()).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), refusals.len());

        assert_eq!(surface_label(true, false), "webchat");
        assert_eq!(surface_label(false, true), "workflow");
        assert_eq!(surface_label(false, false), "internal");
        assert_eq!(action_label(true, "record.read"), "record.read");
    }
}
