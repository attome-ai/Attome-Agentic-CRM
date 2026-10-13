//! The context window: which persisted messages a model call sees, and in
//! what shape (C11 B1, P-1, rows A-72…A-75).
//!
//! Pure — rows in, messages out — so the rules that decide what a model reads
//! are testable without a database. [`crate::conversation::context_messages`]
//! loads the rows and calls [`build`]; nothing else shapes model input from
//! the ledger (I-15).
//!
//! ## The three rules
//!
//! 1. **Newest first.** The window keeps the newest history and drops the
//!    oldest. The current turn — from its user message to the end — is always
//!    in, whatever the limits say: a window that can drop the question it is
//!    answering is the defect this module replaced (`ORDER BY ordinal ASC
//!    LIMIT 40` kept the *first* forty rows).
//! 2. **Whole exchanges.** The unit dropped is the exchange: an assistant
//!    message that asked for tools together with a result for every call it
//!    made. A `tool` message without the assistant message that issued its
//!    `tool_call_id` is a request OpenAI-compatible servers reject, and one a
//!    model would misread anyway.
//! 3. **Bounded by tokens as well as by count.** One oversized result is cut
//!    to [`Limits::max_result_chars`] with an explicit marker, *before* it is
//!    wrapped, so the marker sits inside its untrusted block.
//!
//! ## Every call gets an answer
//!
//! An assistant message's calls do not all produce a `tool` row: the turn can
//! stop for a confirmation, an approval, a revoked session or the step bound
//! before the remaining calls run, and a confirmed call's result is recorded
//! on its `ai_tool_call` row rather than as a message. Each such call is
//! answered from its [`CallFate`] — the stored outcome when it executed, or a
//! fixed, code-authored note saying why it did not — so the replayed structure
//! is always complete and the model is told what really happened.

use std::collections::{HashMap, HashSet};

use attome_inference::ToolCall;
use serde_json::Value;

use crate::conversation::{ContextMessage, Role};

/// The bounds a window is built under.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Most messages, counted after grouping. The current turn is exempt.
    pub max_messages: usize,
    /// Most estimated tokens of history. The current turn is exempt, but its
    /// results are still cut to `max_result_chars`.
    pub max_tokens: u64,
    /// Longest single tool result, in characters, before it is cut.
    pub max_result_chars: usize,
}

/// The defaults a turn runs under.
///
/// Characters are estimated at four per token, the same rate
/// `budget_guard::estimate_tokens` uses, so the window and the budget agree on
/// what a prompt costs. 12k tokens of history leaves room for the frame, the
/// tool definitions and the answer on the 32k-context models a self-hosted
/// deployment typically serves.
pub const DEFAULT_LIMITS: Limits = Limits {
    max_messages: 40,
    max_tokens: 12_000,
    max_result_chars: 12_000,
};

/// How many of the newest rows a rebuild reads. Grouping needs headroom over
/// `max_messages`: an exchange's results can be several rows each.
pub const FETCH_ROWS: i64 = 200;

const CHARS_PER_TOKEN: u64 = 4;

/// One ledger row, as the builder needs it.
#[derive(Debug, Clone)]
pub struct LedgerRow {
    pub role: Role,
    pub content: String,
    /// An assistant row that asked for tools (migration 0488).
    pub tool_calls: Option<Vec<ToolCall>>,
    /// A tool row: the call it answers. `None` on rows written before 0488.
    pub tool_call_id: Option<String>,
}

/// What became of a call that has no `tool` row answering it.
#[derive(Debug, Clone)]
pub struct CallFate {
    /// `ai_tool_call.status`.
    pub status: String,
    /// `ai_tool_call.outcome`, set when it executed.
    pub outcome: Option<Value>,
}

/// The fixed text a call is answered with when no result exists.
///
/// Code-authored and short. It still travels as a tool message, and so is
/// wrapped as untrusted like every tool message — harmless for a fixed string,
/// and it keeps one rendering path.
pub fn fate_text(fate: Option<&CallFate>) -> String {
    let Some(fate) = fate else {
        return "Not run: the turn stopped before this call was made.".to_owned();
    };
    match (fate.status.as_str(), &fate.outcome) {
        ("executed", Some(outcome)) => outcome.to_string(),
        ("executed", None) => "Ran; it returned no result.".to_owned(),
        ("proposed" | "executing", _) => {
            "Not run yet: it is waiting for the user to confirm it.".to_owned()
        }
        ("approval_pending", _) => "Not run yet: it is waiting for approval.".to_owned(),
        ("rejected", _) => "Not run: the user declined it.".to_owned(),
        ("expired", _) => "Not run: nobody confirmed it in time.".to_owned(),
        ("invalidated", _) => "Not run: it was refused when checked again.".to_owned(),
        _ => "Not run.".to_owned(),
    }
}

/// Cuts a result that is over the per-result ceiling, marking the cut.
///
/// Cut on a character boundary, never inside a UTF-8 sequence.
pub fn truncate_result(text: String, max_chars: usize) -> String {
    let total = text.chars().count();
    if total <= max_chars {
        return text;
    }
    let kept: String = text.chars().take(max_chars).collect();
    format!("{kept}\n[truncated: {max_chars} of {total} characters]")
}

fn tokens(messages: &[ContextMessage]) -> u64 {
    let chars: u64 = messages
        .iter()
        .map(|m| {
            m.content.len() as u64
                + m.tool_calls
                    .iter()
                    .map(|c| (c.name.len() + c.arguments.len()) as u64)
                    .sum::<u64>()
        })
        .sum();
    chars.div_ceil(CHARS_PER_TOKEN)
}

/// Builds the window from rows in ascending ordinal order.
pub fn build(
    rows: Vec<LedgerRow>,
    fates: &HashMap<String, CallFate>,
    limits: &Limits,
) -> Vec<ContextMessage> {
    // Which call ids an assistant row in this read issued. A linked tool row
    // whose call is not among them lost its assistant message to the read
    // bound, and goes with it (rule 2).
    let issued: HashSet<&str> = rows
        .iter()
        .filter_map(|r| r.tool_calls.as_ref())
        .flatten()
        .map(|c| c.id.as_str())
        .collect();
    // The first result recorded for each call.
    let mut results: HashMap<String, String> = HashMap::new();
    for row in &rows {
        if let (Role::Tool, Some(id)) = (row.role, row.tool_call_id.as_ref())
            && issued.contains(id.as_str())
        {
            results
                .entry(id.clone())
                .or_insert_with(|| row.content.clone());
        }
    }

    // Group into units. `true` marks a unit that starts with a user message.
    let mut units: Vec<(bool, Vec<ContextMessage>)> = Vec::new();
    for row in rows.iter() {
        match row.role {
            Role::User => units.push((true, vec![ContextMessage::text(Role::User, &row.content)])),
            Role::Assistant => match row.tool_calls.as_ref().filter(|c| !c.is_empty()) {
                Some(calls) => {
                    let mut unit = vec![ContextMessage {
                        role: Role::Assistant,
                        content: row.content.clone(),
                        tool_calls: calls.clone(),
                        tool_call_id: None,
                    }];
                    for call in calls {
                        let text = match results.get(&call.id) {
                            Some(text) => text.clone(),
                            None => fate_text(fates.get(&call.id)),
                        };
                        unit.push(ContextMessage {
                            role: Role::Tool,
                            content: truncate_result(text, limits.max_result_chars),
                            tool_calls: Vec::new(),
                            tool_call_id: Some(call.id.clone()),
                        });
                    }
                    units.push((false, unit));
                }
                // An empty assistant row is a turn that stopped without an
                // answer (awaiting confirmation, a failure). Its terminal
                // state is execution state, not context (I-15), and an empty
                // message teaches the model nothing.
                None if row.content.is_empty() => {}
                None => units.push((
                    false,
                    vec![ContextMessage::text(Role::Assistant, &row.content)],
                )),
            },
            Role::Tool => match row.tool_call_id {
                // Linked: placed with its call above, or dropped with it.
                Some(_) => {}
                // Written before 0488: no link exists, so it stays where it
                // was recorded, as a standalone untrusted block.
                None => units.push((
                    false,
                    vec![ContextMessage::text(
                        Role::Tool,
                        &truncate_result(row.content.clone(), limits.max_result_chars),
                    )],
                )),
            },
        }
    }

    // The current turn: from the last user unit to the end, always kept.
    let current_from = units.iter().rposition(|(user, _)| *user).unwrap_or(0);
    let mut kept_from = current_from;
    let mut count: usize = units[current_from..].iter().map(|(_, u)| u.len()).sum();
    let mut spent: u64 = units[current_from..].iter().map(|(_, u)| tokens(u)).sum();
    // Then older units, newest first, until one does not fit. Never skip an
    // older unit to fit a smaller one before it: a window with a hole in it is
    // a conversation that never happened.
    while kept_from > 0 {
        let (_, unit) = &units[kept_from - 1];
        let (n, t) = (unit.len(), tokens(unit));
        if count + n > limits.max_messages || spent + t > limits.max_tokens {
            break;
        }
        count += n;
        spent += t;
        kept_from -= 1;
    }
    // Start on a user message: some chat templates refuse a history that
    // opens with an assistant or tool turn.
    while kept_from < current_from && !units[kept_from].0 {
        kept_from += 1;
    }

    units
        .into_iter()
        .skip(kept_from)
        .flat_map(|(_, unit)| unit)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(text: &str) -> LedgerRow {
        LedgerRow {
            role: Role::User,
            content: text.into(),
            tool_calls: None,
            tool_call_id: None,
        }
    }
    fn answer(text: &str) -> LedgerRow {
        LedgerRow {
            role: Role::Assistant,
            content: text.into(),
            tool_calls: None,
            tool_call_id: None,
        }
    }
    fn asks(ids: &[&str]) -> LedgerRow {
        LedgerRow {
            role: Role::Assistant,
            content: String::new(),
            tool_calls: Some(
                ids.iter()
                    .map(|id| ToolCall {
                        id: (*id).into(),
                        name: "record.get".into(),
                        arguments: "{}".into(),
                    })
                    .collect(),
            ),
            tool_call_id: None,
        }
    }
    fn result(id: &str, text: &str) -> LedgerRow {
        LedgerRow {
            role: Role::Tool,
            content: text.into(),
            tool_calls: None,
            tool_call_id: Some(id.into()),
        }
    }

    fn limits(max_messages: usize, max_tokens: u64) -> Limits {
        Limits {
            max_messages,
            max_tokens,
            max_result_chars: 10_000,
        }
    }

    fn roles(messages: &[ContextMessage]) -> Vec<&'static str> {
        messages.iter().map(|m| m.role.as_str()).collect()
    }

    /// **Row A-72.** Sixty messages and a sixty-first question: the question
    /// and the newest history are in, and the oldest rows are what went.
    #[test]
    fn the_window_keeps_the_newest_history_and_the_current_question() {
        let mut rows = Vec::new();
        for i in 0..30 {
            rows.push(user(&format!("q{i}")));
            rows.push(answer(&format!("a{i}")));
        }
        rows.push(user("q-current"));
        let window = build(rows, &HashMap::new(), &limits(40, 1_000_000));
        assert_eq!(window.last().unwrap().content, "q-current");
        assert_eq!(
            window.len(),
            39,
            "whole units under the count, starting on a user"
        );
        assert_eq!(
            window[0].content, "q11",
            "the oldest rows are the ones dropped"
        );
        assert!(window.iter().all(|m| m.content != "q0"));
    }

    /// **Row A-73.** Wherever the bound falls, an exchange is whole or absent,
    /// and no tool message appears without the call that issued it.
    #[test]
    fn a_window_boundary_never_splits_an_exchange() {
        for max in 1..12 {
            let rows = vec![
                user("q1"),
                asks(&["c1", "c2", "c3"]),
                result("c1", "r1"),
                result("c2", "r2"),
                result("c3", "r3"),
                answer("a1"),
                user("q2"),
            ];
            let window = build(rows, &HashMap::new(), &limits(max, 1_000_000));
            let issued: HashSet<String> = window
                .iter()
                .flat_map(|m| m.tool_calls.iter().map(|c| c.id.clone()))
                .collect();
            for m in &window {
                if let Some(id) = &m.tool_call_id {
                    assert!(issued.contains(id), "max={max}: orphan result {id}");
                }
            }
            let results = window.iter().filter(|m| m.role == Role::Tool).count();
            assert!(results == 0 || results == 3, "max={max}: split exchange");
            assert_eq!(window.last().unwrap().content, "q2");
        }
    }

    /// **Row A-74.** Native structure, in ledger order: the calls, then one
    /// result per call, each carrying the id it answers.
    #[test]
    fn results_follow_the_call_that_produced_them() {
        let rows = vec![
            user("q1"),
            asks(&["c1", "c2"]),
            result("c2", "second"),
            result("c1", "first"),
            answer("a1"),
            user("q2"),
        ];
        let window = build(rows, &HashMap::new(), &limits(40, 1_000_000));
        assert_eq!(
            roles(&window),
            ["user", "assistant", "tool", "tool", "assistant", "user"]
        );
        assert_eq!(window[1].tool_calls.len(), 2);
        assert_eq!(window[2].tool_call_id.as_deref(), Some("c1"));
        assert_eq!(window[2].content, "first");
        assert_eq!(window[3].tool_call_id.as_deref(), Some("c2"));
    }

    /// A call with no result row is answered from its fate: a confirmed
    /// call's stored outcome, or why it did not run.
    #[test]
    fn a_call_without_a_result_is_answered_from_its_fate() {
        let rows = vec![user("q1"), asks(&["c1", "c2", "c3"]), user("q2")];
        let fates = HashMap::from([
            (
                "c1".to_owned(),
                CallFate {
                    status: "executed".into(),
                    outcome: Some(serde_json::json!({"id": 7})),
                },
            ),
            (
                "c2".to_owned(),
                CallFate {
                    status: "rejected".into(),
                    outcome: None,
                },
            ),
        ]);
        let window = build(rows, &fates, &limits(40, 1_000_000));
        assert_eq!(window[2].content, r#"{"id":7}"#);
        assert!(window[3].content.contains("declined"));
        assert!(window[4].content.contains("stopped before"));
    }

    /// **Row A-75.** The token ceiling bounds history; an oversized result is
    /// cut with a marker; the current question survives regardless.
    #[test]
    fn tokens_bound_history_and_an_oversized_result_is_marked() {
        let big = "x".repeat(40_000);
        let rows = vec![
            user("old question"),
            answer(&"y".repeat(8_000)),
            user("q"),
            asks(&["c1"]),
            result("c1", &big),
        ];
        let window = build(
            rows,
            &HashMap::new(),
            &Limits {
                max_messages: 40,
                max_tokens: 1_000,
                max_result_chars: 5_000,
            },
        );
        assert_eq!(
            window[0].content, "q",
            "older history did not fit the tokens"
        );
        let cut = &window[2].content;
        assert!(cut.ends_with("[truncated: 5000 of 40000 characters]"));
        assert!(cut.chars().count() < 5_100);
    }

    /// A linked result whose assistant message fell outside the read goes
    /// with it; a result written before 0488 stays where it was.
    #[test]
    fn orphaned_results_drop_and_legacy_results_stay_in_place() {
        let rows = vec![
            user("q1"),
            result("gone", "orphan"),
            LedgerRow {
                role: Role::Tool,
                content: "legacy".into(),
                tool_calls: None,
                tool_call_id: None,
            },
            answer("a1"),
            user("q2"),
        ];
        let window = build(rows, &HashMap::new(), &limits(40, 1_000_000));
        let contents: Vec<&str> = window.iter().map(|m| m.content.as_str()).collect();
        assert_eq!(contents, ["q1", "legacy", "a1", "q2"]);
    }

    /// An assistant row with no text and no calls — a turn that stopped for a
    /// human — is not replayed; the window still opens on a user message.
    #[test]
    fn empty_answers_are_skipped_and_the_window_opens_on_a_user() {
        let rows = vec![
            answer("orphaned answer"),
            user("q1"),
            answer(""),
            user("q2"),
        ];
        let window = build(rows, &HashMap::new(), &limits(40, 1_000_000));
        assert_eq!(roles(&window), ["user", "user"]);
    }

    #[test]
    fn truncation_respects_character_boundaries() {
        let arabic = "مرحبا".repeat(10);
        let cut = truncate_result(arabic, 7);
        assert!(cut.starts_with("مرحبامر"));
    }
}
