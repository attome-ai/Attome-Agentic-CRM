//! Website source actions (roadmap K6-T12), both read only. Starting a crawl
//! and opening an intranet host stay with administrators on the webcrawl
//! admin routes; no action here writes, crawls or changes a source.
//!
//! - `webcrawl.propose_scope`: include and exclude patterns proposed from
//!   the pages a crawl found, for a person to put on the source. Local: the
//!   site's sections by page count, with the usual noise (tags, search,
//!   sign-in, feeds) excluded.
//! - `webcrawl.summarise_changes`: what changed on the site in one run, in a
//!   few lines, from the pages that run changed. One model call; a run that
//!   changed nothing makes none.
//!
//! Both need what the webcrawl admin routes need to read
//! (`attome_webcrawl::admin::authorize`) and the agent's read admission for
//! `knowledge_data_source`.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_AI;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult, Provenance};
use crate::prompt::Segment;

pub const PROPOSE_SCOPE: &str = "webcrawl.propose_scope";
pub const SUMMARISE_CHANGES: &str = "webcrawl.summarise_changes";

const SUMMARY_PROMPT_VERSION: &str = "webcrawl.summarise_changes/v1";
/// Pages a scope proposal reads.
const SCOPE_PAGES: i64 = 5000;
/// Sections a proposal includes at most.
const MAX_SECTIONS: usize = 10;
/// A section with fewer pages is not proposed on its own.
const MIN_SECTION_PAGES: usize = 3;
/// Changed pages a summary shows the model, and characters of each.
const SUMMARY_PAGES: i64 = 20;
const SUMMARY_PAGE_CHARS: usize = 600;

/// Path sections that are rarely knowledge.
const NOISE: [&str; 22] = [
    "tag",
    "tags",
    "category",
    "categories",
    "author",
    "authors",
    "page",
    "search",
    "login",
    "logout",
    "signin",
    "sign-in",
    "register",
    "cart",
    "checkout",
    "account",
    "wp-admin",
    "wp-json",
    "feed",
    "rss",
    "print",
    "cdn-cgi",
];

const SCOPE_INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "target_id": { "type": "string", "format": "uuid", "description": "The website source." }
  },
  "required": ["target_id"],
  "additionalProperties": false
}"#;

const SUMMARY_INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "target_id": { "type": "string", "format": "uuid", "description": "The website source." },
    "run_id": { "type": "string", "format": "uuid", "description": "The run; the latest when left out." }
  },
  "required": ["target_id"],
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            PROPOSE_SCOPE,
            "Propose include and exclude path patterns for a website knowledge source from the \
             pages its crawl found: its main sections in, tags, search, sign-in and feeds out. \
             Changes nothing; a person puts the patterns on the source.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(SCOPE_INPUT),
        ActionDescriptor::new(
            SUMMARISE_CHANGES,
            "Summarise in a few lines what changed on a website knowledge source in one crawl \
             run, from the pages that run changed. Changes nothing.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(SUMMARY_INPUT),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(ProposeScope), Box::new(SummariseChanges)]
}

fn uuid_arg(args: &Value, key: &str) -> Result<Option<Uuid>, AppError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_str()
            .and_then(|s| Uuid::parse_str(s.trim()).ok())
            .map(Some)
            .ok_or_else(|| AppError::Validation(format!("{key} must be a UUID"))),
    }
}

/// The caller may read website sources, and the agent may read them.
fn readable(state: &EngineState, ctx: &ActionContext) -> Result<(), AppError> {
    attome_webcrawl::admin::authorize(&ctx.security, attome_webcrawl::admin::Access::Read)?;
    let admitted = crate::mcp::admission::ReadAdmission::for_caller(state, ctx)?
        .is_none_or(|admission| admission.admits("knowledge_data_source"));
    if admitted {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// The first path section, lowercased: `/Blog/2024/x` is `blog`. Pure.
fn section(path: &str) -> Option<String> {
    path.trim_start_matches('/')
        .split(['/', '?', '#'])
        .next()
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase)
}

/// Include and exclude patterns for `paths`, one glob per line as the
/// source stores them. The main sections are proposed for inclusion only
/// when together they hold most of the site's pages; otherwise everything
/// stays in and only the noise goes. Pure.
pub fn propose_scope(paths: &[String]) -> Value {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for path in paths {
        if let Some(s) = section(path) {
            *counts.entry(s).or_default() += 1;
        }
    }
    let noisy = |s: &str| NOISE.contains(&s);
    let mut exclude: Vec<String> = counts
        .keys()
        .filter(|s| noisy(s))
        .flat_map(|s| [format!("/{s}"), format!("/{s}/*")])
        .collect();
    exclude.sort();
    let content: usize = counts
        .iter()
        .filter(|(s, _)| !noisy(s))
        .map(|(_, n)| n)
        .sum();
    let mut main: Vec<(&String, &usize)> = counts
        .iter()
        .filter(|(s, n)| !noisy(s) && **n >= MIN_SECTION_PAGES)
        .collect();
    main.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    main.truncate(MAX_SECTIONS);
    let covered: usize = main.iter().map(|(_, n)| **n).sum();
    let include: Vec<String> = if content > 0 && covered * 10 >= content * 8 {
        main.iter()
            .flat_map(|(s, _)| [format!("/{s}"), format!("/{s}/*")])
            .collect()
    } else {
        Vec::new()
    };
    json!({
        "include_patterns": include.join("\n"),
        "exclude_patterns": exclude.join("\n"),
        "pages": paths.len(),
        "sections": counts
            .iter()
            .map(|(s, n)| json!({ "section": s, "pages": n, "noise": noisy(s) }))
            .collect::<Vec<_>>(),
    })
}

struct ProposeScope;

impl Action for ProposeScope {
    fn id(&self) -> ActionId {
        ActionId(PROPOSE_SCOPE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let target = uuid_arg(args, "target_id")?
                .ok_or_else(|| AppError::Validation("target_id is required".into()))?;
            readable(state, ctx)?;
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM webcrawl_target WHERE id = $1 AND is_deleted = FALSE)",
            )
            .bind(target)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            if !exists {
                return Err(AppError::NotFound);
            }
            let paths: Vec<String> = sqlx::query_scalar(
                "SELECT url_path FROM webcrawl_page \
                  WHERE target_ref = $1 AND is_deleted = FALSE ORDER BY url_path LIMIT $2",
            )
            .bind(target)
            .bind(SCOPE_PAGES)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let mut proposal = propose_scope(&paths);
            proposal["target_id"] = json!(target);
            Ok(ActionResult::plain(proposal))
        })
    }
}

fn summary_system_prompt() -> String {
    "You tell a knowledge manager what changed on a website their knowledge base reads. \
     The passages are pages a crawl found changed, each with its path and the start of its \
     text. Reply with at most five short lines, one change each, naming the page path. \
     Say only what the passages show; do not guess what the page said before. Write in \
     the language most of the pages use."
        .to_owned()
}

struct SummariseChanges;

impl Action for SummariseChanges {
    fn id(&self) -> ActionId {
        ActionId(SUMMARISE_CHANGES)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let target = uuid_arg(args, "target_id")?
                .ok_or_else(|| AppError::Validation("target_id is required".into()))?;
            let run = uuid_arg(args, "run_id")?;
            readable(state, ctx)?;
            type RunRow = (
                Uuid,
                chrono::DateTime<chrono::Utc>,
                Option<chrono::DateTime<chrono::Utc>>,
            );
            let row: Option<RunRow> = sqlx::query_as(
                "SELECT id, started_at, finished_at FROM webcrawl_run \
                  WHERE target_id = $1 AND ($2::uuid IS NULL OR id = $2) \
                  ORDER BY started_at DESC, id DESC LIMIT 1",
            )
            .bind(target)
            .bind(run)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let Some((run_id, started, finished)) = row else {
                return Err(AppError::NotFound);
            };
            let pages: Vec<(String, Option<String>)> = sqlx::query_as(
                "SELECT url_path, content FROM webcrawl_page \
                  WHERE target_ref = $1 AND is_deleted = FALSE \
                    AND updated_at >= $2 AND updated_at <= COALESCE($3, now()) \
                    AND status IN ('crawled', 'document') \
                  ORDER BY url_path LIMIT $4",
            )
            .bind(target)
            .bind(started)
            .bind(finished)
            .bind(SUMMARY_PAGES)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let paths: Vec<&str> = pages.iter().map(|(p, _)| p.as_str()).collect();
            if pages.is_empty() {
                return Ok(ActionResult::plain(json!({
                    "run_id": run_id,
                    "status": "no_changes",
                    "summary": "",
                    "pages": paths,
                })));
            }
            let client = crate::inference_client::client_for(state, SUMMARISE_CHANGES).await?;
            let mut segments = vec![Segment::trusted(summary_system_prompt())];
            for (index, (path, content)) in pages.iter().enumerate() {
                let text: String = content
                    .as_deref()
                    .unwrap_or_default()
                    .chars()
                    .take(SUMMARY_PAGE_CHARS)
                    .collect();
                segments.push(Segment::untrusted(
                    format!("P{}", index + 1),
                    format!("Path: {path}\n\n{text}"),
                ));
            }
            let mut request =
                attome_inference::GenerationRequest::new(crate::prompt::assemble(&segments));
            request.temperature = 0.0;
            crate::model_registry::require_approved_model(
                &state.base.db,
                client.model_id(),
                SUMMARISE_CHANGES,
            )
            .await?;
            let grant = crate::budget_guard::admit(
                state,
                ctx,
                attome_inference::budget::Priority::Chat,
                SUMMARISE_CHANGES,
                &mut request,
            )
            .await?;
            let generated = client.generate(request).await.map_err(|e| {
                tracing::warn!(error = %e, "webcrawl.summarise_changes generation failed");
                AppError::internal("summary generation failed")
            })?;
            grant.settle(state, &generated.usage).await;
            let summary: String = generated.text.trim().chars().take(2000).collect();
            Ok(ActionResult {
                value: json!({
                    "run_id": run_id,
                    "status": "summarised",
                    "summary": summary,
                    "pages": paths,
                }),
                provenance: Some(Provenance {
                    model_id: generated.usage.model_id,
                    prompt_version: SUMMARY_PROMPT_VERSION.to_owned(),
                    suggestion_id: None,
                }),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptors_valid() {
        let ids: Vec<&str> = descriptors().iter().map(|d| d.id.0).collect();
        assert_eq!(ids, vec![PROPOSE_SCOPE, SUMMARISE_CHANGES]);
        assert_eq!(executors().len(), descriptors().len());
        for d in descriptors() {
            assert!(d.description.len() > 40, "{}", d.id.0);
        }
    }

    #[test]
    fn no_write_tool_registered() {
        for d in descriptors() {
            assert_eq!(d.risk, RiskTier::Read, "{}", d.id.0);
            assert_eq!(d.effect, Effect::Read, "{}", d.id.0);
        }
        let all: Vec<String> = crate::actions::all()
            .iter()
            .map(|d| d.id.0.to_owned())
            .filter(|id| id.starts_with("webcrawl."))
            .collect();
        assert_eq!(
            all,
            vec![PROPOSE_SCOPE, SUMMARISE_CHANGES],
            "only the two read tools"
        );
    }

    #[test]
    fn the_main_sections_in_and_the_noise_out() {
        let mut paths: Vec<String> = (0..12).map(|i| format!("/docs/page-{i}")).collect();
        paths.extend((0..5).map(|i| format!("/blog/post-{i}")));
        paths.extend(["/tag/x", "/tag/y", "/search", "/about"].map(str::to_owned));
        let p = propose_scope(&paths);
        assert_eq!(p["include_patterns"], "/docs\n/docs/*\n/blog\n/blog/*");
        assert_eq!(p["exclude_patterns"], "/search\n/search/*\n/tag\n/tag/*");
    }

    #[test]
    fn a_site_without_main_sections_keeps_everything_in() {
        let paths: Vec<String> = (0..10).map(|i| format!("/p{i}")).collect();
        let p = propose_scope(&paths);
        assert_eq!(p["include_patterns"], "");
    }
}
