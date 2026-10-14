//! Red-team fixtures for prompt injection (TODO-052(c), I-10).
//!
//! **These gate P2a.** A chatbot that reads attacker-influenceable text — a
//! record's notes, an email body, a portal submission — and holds tools is the
//! canonical injection target, and read-only agents are not exempt: planted
//! text that steers an answer or a citation is a successful attack that writes
//! nothing.
//!
//! Every payload in `fixtures/injection.json` is run through the whole
//! assembly path and asserted against three properties. The fixture carries a
//! `why` for each, because a red-team corpus nobody can read is one nobody
//! maintains, and the next person adding a payload needs to know which
//! *category* is already covered rather than adding a fourth "ignore previous
//! instructions".
//!
//! ## What these tests do NOT claim
//!
//! They do not claim the model cannot be talked into anything. A sufficiently
//! good injection talks past any instruction, and this suite asserts nothing
//! about model behaviour at all — it asserts the *structural* controls, which
//! are the ones that hold regardless of how the model responds:
//!
//! * planted text never occupies the system role;
//! * planted text cannot escape its delimited block;
//! * an agent-initiated write with such text in context does not auto-execute.
//!
//! The third is the only one that actually bounds damage, and it lives in
//! `gate.rs` rather than here — which is the correct place for it, because it
//! does not depend on the model behaving.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_ai::prompt::{CLOSE, OPEN, Segment, assemble};
use attome_inference::Role;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Payload {
    id: String,
    text: String,
    why: String,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    payloads: Vec<Payload>,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!("fixtures/injection.json")).expect("injection.json parses")
}

/// The corpus covers the categories that matter, not twenty variants of one.
#[test]
fn the_fixture_covers_distinct_attack_categories() {
    let f = fixture();
    assert!(f.payloads.len() >= 15, "too small to be a red-team corpus");

    for p in &f.payloads {
        assert!(
            !p.why.trim().is_empty(),
            "{} has no rationale; a payload nobody can explain is one nobody \
             maintains",
            p.id
        );
    }

    let ids: Vec<&str> = f.payloads.iter().map(|p| p.id.as_str()).collect();
    for required in [
        "delimiter-escape",
        "role-forgery",
        "arabic-override",
        "citation-poisoning",
        "instruction-in-source",
    ] {
        assert!(ids.contains(&required), "missing category {required}");
    }

    // Arabic is not optional coverage here. An injection filter tuned on
    // English is one that does not protect this platform's primary market, and
    // the failure would be silent.
    assert!(
        f.payloads
            .iter()
            .filter(|p| p
                .text
                .chars()
                .any(|c| ('\u{0600}'..='\u{06FF}').contains(&c)))
            .count()
            >= 3,
        "Arabic payloads must be real coverage, not a token case"
    );
}

/// **Property 1.** No payload reaches the system role, in any position.
#[test]
fn no_payload_reaches_the_system_role() {
    for p in fixture().payloads {
        for segments in [
            vec![Segment::untrusted("notes", p.text.clone())],
            vec![
                Segment::trusted("Summarise the record."),
                Segment::untrusted("notes", p.text.clone()),
            ],
            // Planted text FIRST, before the operator's own instruction — the
            // ordering an attacker would choose.
            vec![
                Segment::untrusted("notes", p.text.clone()),
                Segment::trusted("Summarise the record."),
            ],
        ] {
            let messages = assemble(&segments);
            let system: String = messages
                .iter()
                .filter(|m| m.role == Role::System)
                .map(|m| m.content.clone())
                .collect();
            // Compare on a distinctive slice: the whole payload may legitimately
            // fail to appear, but any substantial run of it in the system role
            // is the failure.
            let probe: String = p.text.chars().take(24).collect();
            if probe.trim().len() >= 8 {
                assert!(
                    !system.contains(&probe),
                    "{}: planted text reached the system role ({})",
                    p.id,
                    p.why
                );
            }
        }
    }
}

/// **Property 2.** No payload escapes its delimited block — exactly one closing
/// delimiter, and it is the last thing in the message.
#[test]
fn no_payload_escapes_its_block() {
    for p in fixture().payloads {
        let messages = assemble(&[Segment::untrusted("notes", p.text.clone())]);
        let user = messages
            .iter()
            .find(|m| m.role == Role::User)
            .unwrap_or_else(|| panic!("{}: no user message", p.id));

        assert_eq!(
            user.content.matches(CLOSE).count(),
            1,
            "{}: the block was closed more than once ({})",
            p.id,
            p.why
        );
        assert_eq!(
            user.content.matches(OPEN).count(),
            1,
            "{}: the block was opened more than once ({})",
            p.id,
            p.why
        );
        assert!(
            user.content.trim_end().ends_with(CLOSE),
            "{}: content follows the closing delimiter",
            p.id
        );
        assert!(
            user.content.starts_with(OPEN),
            "{}: content precedes the opening delimiter",
            p.id
        );
    }
}

/// **Property 3.** The payload is still shown to the model.
///
/// The defense is *where* untrusted text appears, not whether the model can
/// read it. A "defense" that stripped the content would break the feature — a
/// summary of a record has to contain the record — and would hide the attack
/// from the human reviewing the answer.
#[test]
fn payloads_are_shown_to_the_model_not_stripped() {
    for p in fixture().payloads {
        if p.text.trim().is_empty()
            || p.text
                .replace(OPEN, "")
                .replace(CLOSE, "")
                .trim()
                .is_empty()
        {
            continue; // nothing left to show once delimiters are removed
        }
        let messages = assemble(&[Segment::untrusted("notes", p.text.clone())]);
        let user = &messages
            .iter()
            .find(|m| m.role == Role::User)
            .unwrap()
            .content;
        let probe: String = p
            .text
            .replace(OPEN, "")
            .replace(CLOSE, "")
            .chars()
            .take(16)
            .collect();
        if probe.trim().len() >= 8 {
            assert!(
                user.contains(probe.trim()),
                "{}: the content was stripped rather than delimited — the model \
                 must SEE it, or the feature is broken and the attack is hidden \
                 from the human reviewing the answer",
                p.id
            );
        }
    }
}

/// A payload in the *source label* is handled like one in the body.
///
/// The label comes from an entity name or a document title, both
/// attacker-influenceable, and it is interpolated straight into the delimiter
/// line — a place it is easy to forget while sanitizing the obvious field.
#[test]
fn a_payload_in_the_source_label_cannot_escape_either() {
    for p in fixture().payloads {
        let messages = assemble(&[Segment::untrusted(p.text.clone(), "ordinary body text")]);
        let user = &messages
            .iter()
            .find(|m| m.role == Role::User)
            .unwrap()
            .content;
        assert_eq!(
            user.matches(CLOSE).count(),
            1,
            "{}: via the source label",
            p.id
        );
        assert_eq!(
            user.matches(OPEN).count(),
            1,
            "{}: via the source label",
            p.id
        );
    }
}

/// The warning is present whenever any payload is shown, and names both
/// delimiters so the instruction refers to something the model can see.
#[test]
fn the_standing_warning_accompanies_every_payload() {
    for p in fixture().payloads {
        let messages = assemble(&[
            Segment::trusted("Summarise the record."),
            Segment::untrusted("notes", p.text.clone()),
        ]);
        let system = &messages[0].content;
        assert!(system.contains(OPEN) && system.contains(CLOSE), "{}", p.id);
    }
}

/// **M98 Phase 1's write-attempt extension (plan §7).** Every payload, run
/// against the platform's real registered write action —
/// `record.update_field` — rather than a synthetic descriptor. Ties the
/// prompt-assembly taint this file otherwise tests in isolation to the
/// actual gate outcome a planted-text write attempt produces: `ConfirmFirst`,
/// never `Execute` and never `ApprovalRequired` (a silent downgrade to a
/// weaker control would be just as wrong as no control at all).
///
/// `write-instruction` is the payload written for exactly this case
/// (`fixtures/injection.json`'s own `why`), but every payload is run, not
/// only that one — the property under test is "planted text anywhere taints
/// the context enough to degrade a write", not "this one payload happens
/// to look like a write instruction".
#[test]
fn every_payload_degrades_a_real_agent_write_to_confirm_first() {
    use attome_ai::actions::record_update_field::RECORD_UPDATE_FIELD;
    use attome_ai::context::ActionContext;
    use attome_ai::descriptor::RiskTier;
    use attome_ai::gate::{self, ConfirmReason, GateDecision, GateInputs};
    use attome_ai::registry::ActionRegistry;
    use attome_config::AiEnablement;

    let registry = ActionRegistry::new();
    let descriptor = registry
        .resolve(RECORD_UPDATE_FIELD)
        .expect("record.update_field must be registered");
    let ai = AiEnablement {
        enabled: true,
        fields: true,
        chat: true,
        semantic_search: true,
        workflow_nodes: true,
    };
    let inputs = GateInputs {
        licensed: true,
        ai: &ai,
        surface: None,
        external_effects_enabled: false,
    };

    for p in fixture().payloads {
        // The payload arrives as a tool result in the model's context — the
        // shape a real injected write attempt takes (planted in a record's
        // notes, a search hit, anything the agent reads before deciding to
        // write). `turn::run` marks the context tainted as soon as any tool
        // message is in the history (I-10); the payload's own content is
        // incidental to this property, so the context below is tainted
        // exactly as the loop would taint it.
        let security = std::sync::Arc::new(attome_server::security::SecurityContext {
            user_id: uuid::Uuid::now_v7(),
            is_admin: true,
            privileges: std::collections::HashSet::new(),
            field_grants: std::collections::HashSet::new(),
            field_write_grants: std::collections::HashSet::new(),
            bulk_fields: Default::default(),
            epoch: 0,
            accessible_org_ids: Vec::new(),
            team_ids: Vec::new(),
            position_hierarchy_enabled: false,
            subordinate_user_ids: Vec::new(),
            condition_grants: std::collections::HashMap::new(),
            role_ids: None,
            service_principal: false,
        });
        let ctx = ActionContext::agent(security, RiskTier::Reversible).tainted();

        let decision = gate::evaluate(descriptor, &ctx, &inputs);
        assert_eq!(
            decision,
            Ok(GateDecision::ConfirmFirst {
                reason: ConfirmReason::RetrievedContentInContext
            }),
            "{}: a tainted agent write to record.update_field must degrade to \
             confirm-first, never auto-execute and never silently downgrade \
             to a weaker control ({})",
            p.id,
            p.why
        );
    }
}

/// **TODO-040's verify line, for the half that can be asserted deterministically.**
///
/// The injected-content fixtures run through the *turn loop's* prompt-assembly
/// path — `turn::assemble_messages` over a history whose tool message carries
/// each payload — rather than through `assemble` directly. That is the path
/// every conversational turn actually uses, and the two could drift: a loop
/// that replayed a tool result outside `render_untrusted` would pass every
/// test above and fail here.
///
/// Three properties, per payload:
///
/// 1. planted text never reaches the system role;
/// 2. the replayed tool result stays inside exactly one untrusted block, and
///    the system message carries the standing warning;
/// 3. **the tool set does not change** — `turn::tool_definitions` is derived
///    from the registry in Rust, so no text in a tool *result* can add,
///    remove, or rename a tool. This is the concrete form of "planted
///    instructions must not alter tool selection".
///
/// What this does **not** assert is model behaviour — no model runs here. The
/// end-to-end half of TODO-040's verify line needs a live inference stack and
/// is recorded as outstanding rather than implied by this test.
#[test]
fn injected_tool_results_change_neither_the_system_prompt_nor_the_tool_set() {
    use attome_ai::conversation::{ContextMessage, Role as LedgerRole};
    use attome_ai::registry::ActionRegistry;
    use attome_ai::turn::{assemble_messages, system_frame, tool_definitions};
    use attome_inference::{ChatMessage, ToolCall};

    let registry = ActionRegistry::new();
    let baseline = tool_definitions(registry.all());
    assert!(
        !baseline.is_empty(),
        "the loop must have tools to begin with"
    );

    for p in fixture().payloads {
        let history = vec![
            ContextMessage::text(LedgerRole::User, "What do the notes on Acme say?"),
            ContextMessage {
                role: LedgerRole::Assistant,
                content: String::new(),
                tool_calls: vec![ToolCall {
                    id: "call_1".into(),
                    name: "search.records".into(),
                    arguments: "{}".into(),
                }],
                tool_call_id: None,
            },
            ContextMessage {
                role: LedgerRole::Tool,
                content: p.text.clone(),
                tool_calls: Vec::new(),
                tool_call_id: Some("call_1".into()),
            },
        ];
        let messages: Vec<ChatMessage> = assemble_messages(&system_frame(), None, history);

        // (1) The system prompt.
        let system: String = messages
            .iter()
            .filter(|m| m.role == Role::System)
            .map(|m| m.content.clone())
            .collect();
        let probe: String = p.text.chars().take(24).collect();
        if probe.trim().len() >= 8 {
            assert!(
                !system.contains(&probe),
                "{}: a tool result reached the system role ({})",
                p.id,
                p.why
            );
        }

        // (2) The replayed result is one delimited block.
        let tool_message = messages
            .iter()
            .find(|m| m.role == Role::Tool)
            .unwrap_or_else(|| panic!("{}: the tool result was not replayed", p.id));
        assert_eq!(
            tool_message.content.matches(OPEN).count(),
            1,
            "{}: the tool result must open exactly one untrusted block",
            p.id
        );
        assert_eq!(
            tool_message.content.matches(CLOSE).count(),
            1,
            "{}: the tool result closed its own block ({})",
            p.id,
            p.why
        );
        assert!(
            tool_message.content.trim_end().ends_with(CLOSE),
            "{}: text escaped past the end of the untrusted block",
            p.id
        );

        // (3) The tool set. Decided in Rust from the registry — nothing in a
        // tool result can reach it.
        assert_eq!(
            tool_definitions(registry.all()),
            baseline,
            "{}: the tool set changed after an injected tool result",
            p.id
        );
    }
}

/// **D-503 §6 — persona-borne injection.** Every payload in the corpus is used
/// as an agent's administrator-edited persona and assembled into the
/// playground prompt, the one place a persona reaches a model today. Per
/// payload:
///
/// 1. the code-owned frame begins the system message — a persona never
///    precedes or replaces it;
/// 2. the persona stays inside exactly one persona block, and that block ends
///    the system message, so nothing it says can be placed after it;
/// 3. persona text cannot forge an untrusted-data block, and the
///    administrator's message is the only user turn.
///
/// Like the rest of this file, this asserts structure, not model behaviour.
#[test]
fn no_persona_payload_precedes_or_escapes_the_code_owned_frame() {
    use attome_ai::actions::agent_playground::{playground_messages, playground_system_prompt};
    use attome_ai::prompt::{PERSONA_CLOSE, PERSONA_OPEN};

    let frame = playground_system_prompt();
    for p in fixture().payloads {
        let messages = playground_messages(&p.text, "hello");
        assert_eq!(messages.len(), 2, "{}", p.id);
        assert_eq!(messages[0].role, Role::System, "{}", p.id);
        let system = &messages[0].content;

        assert!(
            system.starts_with(&frame),
            "{}: the code-owned frame must lead the system message ({})",
            p.id,
            p.why
        );
        assert_eq!(
            system.matches(PERSONA_OPEN).count(),
            1,
            "{}: the persona opened a second block",
            p.id
        );
        assert_eq!(
            system.matches(PERSONA_CLOSE).count(),
            1,
            "{}: the persona closed its block early",
            p.id
        );
        assert!(
            system.find(PERSONA_OPEN).expect("persona block") >= frame.len(),
            "{}: the persona block must follow the frame",
            p.id
        );
        assert!(
            system.trim_end().ends_with(PERSONA_CLOSE),
            "{}: content follows the persona block ({})",
            p.id,
            p.why
        );
        assert!(
            !system.contains(OPEN) && !system.contains(CLOSE),
            "{}: a persona forged an untrusted-data block",
            p.id
        );
        assert_eq!(messages[1].role, Role::User, "{}", p.id);
        assert_eq!(messages[1].content, "hello", "{}", p.id);
    }
}

/// The place a persona reaches a model holds no authority for it to claim: the
/// playground is a Read-tier action with no privileges and no write path, so
/// persona text like `persona-permission-grant` has nothing to unlock. What an
/// agent session may do is decided by the gate (D-503 §2), not by any prompt.
#[test]
fn the_persona_path_holds_no_authority_a_persona_could_claim() {
    use attome_ai::actions::agent_playground::descriptor;
    use attome_ai::descriptor::{Effect, RiskTier};

    let d = descriptor();
    assert_eq!(d.risk, RiskTier::Read);
    assert_eq!(d.effect, Effect::Read);
    assert!(d.required_privileges.is_empty());
}
