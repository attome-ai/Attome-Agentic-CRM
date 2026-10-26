//! Read-only prompt registry surface (D-435) — `GET /api/v1/admin/ai/prompts`
//! and its diff sibling.
//!
//! **Prompts are code, so the surface is read-only.** Every prompt lives as a
//! versioned Rust function next to the action that uses it
//! (`actions::read::summarize_system_prompt`,
//! `actions::draft_article::draft_system_prompt`) — D-360 ruling 4: "a prompt
//! is code, reviewed like code, and a deployment must not be able to edit one
//! into something the red-team fixtures never covered." This module does not
//! change that; it only lets an admin SEE what shipped, without reading Rust
//! source. There is deliberately no write path here — editing a prompt means
//! changing the function and bumping its `*_PROMPT_VERSION` constant, the
//! same discipline every prompt module's own doc comment already states
//! ("a prompt change without a version bump silently merges two populations
//! in every later quality comparison").
//!
//! **The registry is forward-compatible with real version history.** Today
//! each prompt has shipped exactly one version, so [`all_versions`] lists one
//! entry per prompt. The day a prompt's wording changes, the old constant's
//! *string* retires but its entry can be kept here (a `v1` alongside the new
//! `v2`) so [`diff`] keeps working against real history instead of only ever
//! comparing a version against itself. Nothing about this module's shape
//! needs to change to support that — it is exactly what an admin auditing "we
//! changed the prompt and quality dropped" (`quality_monitor.rs`) needs to be
//! able to compare against.

use attome_types::AppError;
use serde::Serialize;
use utoipa::ToSchema;

/// One prompt_version this build ships, rendered with a fixed reference
/// language so the admin surface shows real text rather than an unfilled
/// template. The RUNTIME prompt for a non-English caller differs only in
/// that substitution — structure (and therefore what a diff reveals) is
/// identical, since every prompt function's language parameter only ever
/// touches the "Write in {language}" instruction.
const REFERENCE_LANGUAGE: &str = "English";

pub struct PromptEntry {
    pub action_id: &'static str,
    pub version: &'static str,
    pub text: String,
}

impl std::fmt::Debug for PromptEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PromptEntry").finish_non_exhaustive()
    }
}

/// Every prompt_version this build ships. Adding a prompt means adding one
/// line here — the same place `crate::actions::all_executors` requires a new
/// action's executor to be registered, so a prompt cannot silently exist
/// without appearing on this admin surface.
pub fn all_versions() -> Vec<PromptEntry> {
    vec![
        PromptEntry {
            action_id: crate::actions::read::RECORD_SUMMARIZE,
            version: crate::actions::read::SUMMARIZE_PROMPT_VERSION,
            text: crate::actions::read::summarize_system_prompt(REFERENCE_LANGUAGE),
        },
        PromptEntry {
            action_id: crate::actions::draft_article::ARTICLE_DRAFT,
            version: crate::actions::draft_article::DRAFT_PROMPT_VERSION,
            text: crate::actions::draft_article::draft_system_prompt(REFERENCE_LANGUAGE),
        },
        PromptEntry {
            action_id: crate::actions::duplicates::DUPLICATES_PROPOSE_RULES,
            version: crate::actions::duplicates::PROPOSE_RULES_PROMPT_VERSION,
            text: crate::actions::duplicates::propose_rules_system_prompt(),
        },
        PromptEntry {
            action_id: crate::actions::classify::RECORD_CLASSIFY,
            version: crate::actions::classify::CLASSIFY_PROMPT_VERSION,
            // Rendered with a representative two-value choice list so the
            // admin surface shows real structure rather than an empty list —
            // the actual runtime prompt enumerates whatever the target
            // field's own `ChoiceOptions` configure.
            text: crate::actions::classify::classify_system_prompt(
                "status",
                &["open".to_string(), "closed".to_string()],
            ),
        },
        PromptEntry {
            action_id: crate::actions::route_classify::ROUTE_CLASSIFY,
            version: crate::actions::route_classify::ROUTE_CLASSIFY_PROMPT_VERSION,
            // Rendered with a representative two-route list, same reasoning
            // as the entry above — the actual runtime prompt enumerates
            // whatever the `Route` node's own `config.routes` configure.
            text: crate::actions::route_classify::route_system_prompt(
                &["urgent".to_string(), "normal".to_string()],
                None,
            ),
        },
        PromptEntry {
            action_id: crate::actions::agent_playground::AGENT_PLAYGROUND_COMPLETE,
            version: crate::actions::agent_playground::AGENT_PLAYGROUND_PROMPT_VERSION,
            // The code-owned frame only. The definition's persona is added at
            // runtime as a separate typed segment (D-503 §6).
            text: crate::actions::agent_playground::playground_system_prompt(),
        },
        PromptEntry {
            action_id: crate::actions::catalog::CATALOG_ASK,
            version: crate::actions::catalog::ASK_PROMPT_VERSION,
            text: crate::actions::catalog::ask_system_prompt(),
        },
        PromptEntry {
            action_id: crate::actions::search_ask::SEARCH_PARSE_FILTER,
            version: crate::actions::search_ask::PARSE_PROMPT_VERSION,
            // The caller's readable metadata goes in its own untrusted segment.
            text: crate::actions::search_ask::parse_system_prompt(),
        },
        PromptEntry {
            action_id: crate::actions::search_ask::SEARCH_ANSWER_RECORDS,
            version: crate::actions::search_ask::RECORDS_ANSWER_PROMPT_VERSION,
            text: crate::actions::search_ask::records_answer_system_prompt(),
        },
        PromptEntry {
            action_id: crate::actions::knowledge_answer::KNOWLEDGE_ANSWER,
            version: crate::actions::knowledge_answer::ANSWER_PROMPT_VERSION,
            // No language parameter: the prompt tells the model to answer in
            // the question's own language.
            text: crate::actions::knowledge_answer::answer_system_prompt(),
        },
        PromptEntry {
            action_id: crate::actions::draft_page::PAGE_DRAFT,
            version: crate::actions::draft_page::PAGE_DRAFT_PROMPT_VERSION,
            // Rendered for a custom page; at runtime the page type and a
            // record page's entity id are filled in.
            text: crate::actions::draft_page::page_draft_system_prompt(
                &attome_metadata::model_edit::registry()
                    .get("page")
                    .map(|kind| kind.json_schema())
                    .unwrap_or_default(),
                "custom",
                None,
            ),
        },
        PromptEntry {
            action_id: crate::actions::translate::TEXT_TRANSLATE,
            version: crate::actions::translate::TRANSLATE_PROMPT_VERSION,
            // Rendered into Arabic with no glossary; at runtime the terms
            // found in the text are appended.
            text: crate::actions::translate::translate_system_prompt(
                None,
                "ar",
                &std::collections::BTreeMap::new(),
            ),
        },
        PromptEntry {
            action_id: crate::actions::ai_field::RECORD_AI_FIELD,
            version: crate::actions::ai_field::AI_FIELD_PROMPT_VERSION,
            // Rendered with a representative prompt; the real instruction is
            // the attribute's own `options.ai.prompt`.
            text: crate::actions::ai_field::instruction(
                "summary",
                "Summarise {{description}} in one line.",
            ),
        },
        PromptEntry {
            action_id: crate::meeting::brief::MEETING_BRIEF,
            version: crate::meeting::brief::BRIEF_PROMPT_VERSION,
            // English shown; an Arabic meeting gets the same frame in Arabic.
            text: crate::meeting::brief::brief_system_prompt("en"),
        },
        PromptEntry {
            action_id: crate::meeting::notes::MEETING_NOTES,
            version: crate::meeting::notes::NOTES_PROMPT_VERSION,
            // Rendered with a representative record list; the runtime one
            // names the meeting's own records.
            text: crate::meeting::notes::notes_system_prompt("en", "opportunity <id>"),
        },
        PromptEntry {
            // The merge step of a long transcript's notes.
            action_id: crate::meeting::notes::MEETING_NOTES_MERGE,
            version: crate::meeting::notes::MERGE_PROMPT_VERSION,
            text: crate::meeting::notes::merge_system_prompt("en"),
        },
        PromptEntry {
            // Not a registered action: AI5-T4's promise reader, spent as
            // `collections.record_promise`.
            action_id: crate::followup_promise::EXTRACT_PROMPT_ID,
            version: crate::followup_promise::EXTRACT_PROMPT_VERSION,
            text: crate::followup_promise::extract_system_prompt(),
        },
        PromptEntry {
            // Not a registered action: the conversational turn itself
            // (`turn::run`). Its version keys C10-C's live-evaluation
            // baselines, so an admin comparing a quality change needs to see
            // the frame it names. The persona is a separate typed segment
            // added at runtime (D-595), never part of this text.
            action_id: TURN_PROMPT_ID,
            version: crate::turn::TURN_PROMPT_VERSION,
            text: crate::turn::system_frame(),
        },
    ]
}

/// The registry's id for the conversational turn's frame (see [`all_versions`]).
pub const TURN_PROMPT_ID: &str = "assistant.turn";

pub fn find_version(version: &str) -> Option<PromptEntry> {
    all_versions().into_iter().find(|p| p.version == version)
}

/// One line of a line-based diff between two prompt versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum DiffLine {
    Same { text: String },
    Added { text: String },
    Removed { text: String },
}

/// A minimal LCS-based line diff — the same algorithm shape a `diff -u` uses,
/// simplified to unmerged Added/Removed/Same lines rather than hunks with
/// context windows, because prompt texts here are short (a few dozen lines)
/// and an admin reading this wants "what changed", not a patch file.
///
/// `O(n*m)` in line count, which is fine at this scale — these are prompt
/// templates, not file diffs over large documents.
pub fn diff_lines(from: &str, to: &str) -> Vec<DiffLine> {
    let a: Vec<&str> = from.lines().collect();
    let b: Vec<&str> = to.lines().collect();
    let n = a.len();
    let m = b.len();

    let mut lcs = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }

    let mut result = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if a[i] == b[j] {
            result.push(DiffLine::Same {
                text: a[i].to_string(),
            });
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            result.push(DiffLine::Removed {
                text: a[i].to_string(),
            });
            i += 1;
        } else {
            result.push(DiffLine::Added {
                text: b[j].to_string(),
            });
            j += 1;
        }
    }
    while i < n {
        result.push(DiffLine::Removed {
            text: a[i].to_string(),
        });
        i += 1;
    }
    while j < m {
        result.push(DiffLine::Added {
            text: b[j].to_string(),
        });
        j += 1;
    }
    result
}

/// Diffs two registered prompt_versions by name. Either name unresolved is a
/// client error (`AppError::Validation`), not `NotFound` — this surface is
/// admin-only and there is nothing dark to protect here (unlike
/// `model_registry`'s gate), so naming the bad version in the message is the
/// actionable behaviour guidelines §6 asks for.
pub fn diff(from_version: &str, to_version: &str) -> Result<Vec<DiffLine>, AppError> {
    let from = find_version(from_version)
        .ok_or_else(|| AppError::Validation(format!("unknown prompt_version: {from_version}")))?;
    let to = find_version(to_version)
        .ok_or_else(|| AppError::Validation(format!("unknown prompt_version: {to_version}")))?;
    Ok(diff_lines(&from.text, &to.text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_shipped_prompt_appears_exactly_once() {
        let versions = all_versions();
        assert!(!versions.is_empty());
        let mut seen = std::collections::HashSet::new();
        for p in &versions {
            assert!(
                seen.insert(p.version),
                "prompt_version {} appears more than once in the registry",
                p.version
            );
            assert!(!p.text.trim().is_empty());
        }
    }

    #[test]
    fn diffing_a_version_against_itself_is_all_same_lines() {
        let versions = all_versions();
        let v = &versions[0];
        let lines = diff_lines(&v.text, &v.text);
        assert!(
            lines.iter().all(|l| matches!(l, DiffLine::Same { .. })),
            "a prompt diffed against itself must show no changes"
        );
    }

    #[test]
    fn diff_reports_added_and_removed_lines() {
        let from = "line one\nline two\nline three";
        let to = "line one\nline two changed\nline three\nline four";
        let lines = diff_lines(from, to);

        assert!(lines.contains(&DiffLine::Same {
            text: "line one".to_string()
        }));
        assert!(lines.contains(&DiffLine::Removed {
            text: "line two".to_string()
        }));
        assert!(lines.contains(&DiffLine::Added {
            text: "line two changed".to_string()
        }));
        assert!(lines.contains(&DiffLine::Same {
            text: "line three".to_string()
        }));
        assert!(lines.contains(&DiffLine::Added {
            text: "line four".to_string()
        }));
    }

    #[test]
    fn diffing_an_unknown_version_is_a_validation_error_naming_it() {
        let err = diff("nonexistent/v1", "also-nonexistent/v1").unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(msg.contains("nonexistent/v1")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn the_conversational_turn_frame_is_listed_under_its_version() {
        let entry = find_version(crate::turn::TURN_PROMPT_VERSION).expect("turn frame registered");
        assert_eq!(entry.action_id, TURN_PROMPT_ID);
        assert_eq!(entry.text, crate::turn::system_frame());
    }

    /// The language substitution must not be the only difference a diff
    /// against a hypothetical differently-languaged render would show — this
    /// pins that the registry always renders with the one fixed reference
    /// language, so two calls to `all_versions()` never disagree with
    /// themselves.
    #[test]
    fn rendering_is_stable_across_calls() {
        let a = all_versions();
        let b = all_versions();
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.version, y.version);
            assert_eq!(x.text, y.text);
        }
    }
}
