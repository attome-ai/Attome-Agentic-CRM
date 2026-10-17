//! Drafts for agents (roadmap D25-T8): a battle card read, a win-loss review
//! drafted from a deal's history, and a battle card update drafted from the
//! losses against a competitor. Everything here only reads, as the caller,
//! and returns material a person saves or publishes; nothing is written.
//!
//! - Records are read through `attome_records::entity_crud::read_record_bulk`,
//!   the same read `record.get` uses, so record rules and field grants apply
//!   exactly as on screen.
//! - The notes, emails and call findings a review draft quotes are picked
//!   with the caller's record rules on their own entity (an entity the
//!   caller may not read, or one not installed, is skipped), then read one by
//!   one through the same read for their field grants.
//! - Review reasons only map onto the review's own choices; a deal reason
//!   with no match (a lost deal's `no_budget`, say) is left for the person.

use attome_core::EngineState;
use attome_records::entity_crud::read_record_bulk;
use attome_security::{
    RecordAction, SecurityContextExt, bind_rls_predicate_as, resolve_entity_access_level,
    rls_predicate,
};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use crate::competitor_routes::{SalesBattlecard, battlecards};

/// Notes, emails and call findings each a review draft quotes, newest first.
pub const DRAFT_SOURCES: i64 = 10;

/// Loss reviews a battle card update reads, newest first.
pub const LOSS_REVIEWS: i64 = 20;

/// Characters kept from one quoted note, email or finding.
pub const QUOTE_CHARS: usize = 600;

/// The review's `main_reason` choices.
pub const REVIEW_REASONS: [&str; 6] = [
    "price",
    "product_fit",
    "relationship",
    "timing",
    "procurement",
    "other",
];

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompetitorCard {
    pub competitor_id: Uuid,
    /// The competitor's fields the caller may read (name, strengths,
    /// weaknesses, price position, regions, battle card id).
    pub competitor: Value,
    /// The knowledge article holding the battle card, when one is set, the
    /// deployment names its article entity and the caller may read it.
    pub article: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DraftQuote {
    /// `note`, `communication` or `call_finding`.
    pub source: &'static str,
    pub id: Uuid,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReviewDraft {
    pub opportunity_id: Uuid,
    /// Always true: nothing was saved.
    pub draft: bool,
    /// Field values for a new `win_loss_review`; `None` is for the person.
    pub outcome: Option<&'static str>,
    pub main_reason: Option<&'static str>,
    pub lost_to_competitor_ref: Option<Uuid>,
    pub competitors_snapshot: Vec<SalesBattlecard>,
    /// What the draft was read from, for the agent to write the review's
    /// text fields and for the person to check them.
    pub quotes: Vec<DraftQuote>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReasonCount {
    pub reason: String,
    pub count: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BattlecardUpdateDraft {
    pub competitor_id: Uuid,
    /// Always true: nothing was published.
    pub draft: bool,
    pub battlecard_ref: Option<String>,
    pub losses_read: usize,
    pub reasons: Vec<ReasonCount>,
    pub winner_did_better: Vec<String>,
    /// A starting text for the card's owner to edit and publish.
    pub text: String,
}

/// The review reason a deal's own won or lost reason maps onto, if any.
pub fn review_reason(outcome: &str, deal_reason: &str) -> Option<&'static str> {
    match (outcome, deal_reason) {
        (_, "price") => Some("price"),
        (_, "timing") => Some("timing"),
        (_, "other") => Some("other"),
        ("won", "product_fit") | ("lost", "product_gap") => Some("product_fit"),
        ("won", "relationship") => Some("relationship"),
        ("won", "service") => Some("other"),
        _ => None,
    }
}

fn clip(text: &str) -> String {
    let text = text.trim();
    match text.char_indices().nth(QUOTE_CHARS) {
        Some((at, _)) => format!("{}…", &text[..at]),
        None => text.to_owned(),
    }
}

fn text_of(data: &Value, field: &str) -> Option<String> {
    data.get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// A record's readable fields, or `None` when the caller may not read it.
async fn readable_data(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    id: Uuid,
) -> Result<Option<Value>, AppError> {
    match read_record_bulk(state, ctx, entity, id).await {
        Ok(record) => {
            let value = serde_json::to_value(record).map_err(AppError::internal)?;
            Ok(Some(value.get("data").cloned().unwrap_or(Value::Null)))
        }
        Err(AppError::NotFound | AppError::Forbidden) => Ok(None),
        Err(e) => Err(e),
    }
}

/// A competitor's card as `ctx` may read it.
pub async fn battlecard(
    state: &EngineState,
    ctx: &SecurityContext,
    competitor: Uuid,
) -> Result<CompetitorCard, AppError> {
    let data = readable_data(state, ctx, "competitor", competitor)
        .await?
        .ok_or(AppError::NotFound)?;
    let mut article = None;
    let article_id = text_of(&data, "battlecard_ref").and_then(|s| s.parse::<Uuid>().ok());
    let article_entity = state.base.config.inference.knowledge_article_entity.clone();
    if let (Some(id), Some(entity)) = (article_id, article_entity) {
        article = readable_data(state, ctx, &entity, id).await?;
    }
    Ok(CompetitorCard {
        competitor_id: competitor,
        competitor: data,
        article,
    })
}

/// Up to [`DRAFT_SOURCES`] ids of `entity` rows about `deal` that `ctx` may
/// read. `base` selects one id column aliased by `alias`, takes the deal as
/// `$1` (text) and leaves room for the record rules from `$2`.
async fn readable_ids(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    alias: &str,
    base: &str,
    order: &str,
    deal: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    let Some(entity_id) = state.entities.load().get(entity).map(|m| m.entity_id) else {
        return Ok(Vec::new());
    };
    if ctx.require(entity, "read").is_err() {
        return Ok(Vec::new());
    }
    let db = &state.base.db;
    let level =
        resolve_entity_access_level(db, ctx.user_id, entity_id, entity, RecordAction::Read).await?;
    let predicate = rls_predicate(
        ctx,
        entity_id,
        alias,
        level,
        RecordAction::Read.share_capability(),
        2,
    );
    let rls = predicate.as_ref().map_or("", |p| p.sql.as_str());
    let sql = format!("{base} {rls} ORDER BY {order} LIMIT {DRAFT_SOURCES}");
    let mut query = sqlx::query_as::<_, (Uuid,)>(&sql).bind(deal.to_string());
    if let Some(p) = &predicate {
        query = bind_rls_predicate_as(query, &p.binds);
    }
    Ok(query
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?
        .into_iter()
        .map(|(id,)| id)
        .collect())
}

/// One quote per readable row, its text joined from `fields`.
async fn quotes(
    state: &EngineState,
    ctx: &SecurityContext,
    source: &'static str,
    ids: Vec<Uuid>,
    fields: &[&str],
) -> Result<Vec<DraftQuote>, AppError> {
    let mut out = Vec::new();
    for id in ids {
        let Some(data) = readable_data(state, ctx, source, id).await? else {
            continue;
        };
        let text = fields
            .iter()
            .filter_map(|f| text_of(&data, f))
            .collect::<Vec<_>>()
            .join(" ");
        if !text.is_empty() {
            out.push(DraftQuote {
                source,
                id,
                text: clip(&text),
            });
        }
    }
    Ok(out)
}

/// A win-loss review drafted from a deal's history, as `ctx` may read it.
/// Nothing is saved.
pub async fn review_draft(
    state: &EngineState,
    ctx: &SecurityContext,
    deal: Uuid,
) -> Result<ReviewDraft, AppError> {
    let data = readable_data(state, ctx, "opportunity", deal)
        .await?
        .ok_or(AppError::NotFound)?;
    let outcome = text_of(&data, "stage")
        .as_deref()
        .and_then(crate::win_loss::outcome_of);
    let main_reason = outcome.and_then(|o| {
        let field = if o == "won" {
            "won_reason"
        } else {
            "lost_reason"
        };
        text_of(&data, field).and_then(|r| review_reason(o, &r))
    });
    let lost_to = text_of(&data, "lost_to_competitor_ref").and_then(|s| s.parse().ok());
    // Competitors are an optional part of the sales pack.
    let competitors_snapshot = match battlecards(state, ctx, deal).await {
        Ok(cards) => cards,
        Err(AppError::NotFound) => Vec::new(),
        Err(e) => return Err(e),
    };
    let live = |a: &str| format!("({a}.is_active IS NULL OR {a}.is_active = true)");
    let mut all = Vec::new();
    let notes = readable_ids(
        state,
        ctx,
        "note",
        "n",
        &format!(
            "SELECT n.id FROM note n WHERE n.entity_name = 'opportunity' \
             AND n.record_id = $1 AND {}",
            live("n")
        ),
        "n.created_at DESC, n.id DESC",
        deal,
    )
    .await?;
    all.extend(quotes(state, ctx, "note", notes, &["title", "note_text"]).await?);
    let emails = readable_ids(
        state,
        ctx,
        "communication",
        "c",
        &format!(
            "SELECT c.id FROM communication c WHERE c.entity_name = 'opportunity' \
             AND c.record_id = $1 AND {}",
            live("c")
        ),
        "c.created_at DESC, c.id DESC",
        deal,
    )
    .await?;
    all.extend(quotes(state, ctx, "communication", emails, &["subject", "body"]).await?);
    let findings = readable_ids(
        state,
        ctx,
        "call_finding",
        "f",
        &format!(
            "SELECT f.id FROM call_finding f JOIN call_analysis a ON a.id = f.analysis_ref \
             WHERE a.opportunity_id = $1 AND {} AND {}",
            live("f"),
            live("a")
        ),
        "f.created_at DESC, f.id DESC",
        deal,
    )
    .await?;
    all.extend(quotes(state, ctx, "call_finding", findings, &["kind", "text"]).await?);
    Ok(ReviewDraft {
        opportunity_id: deal,
        draft: true,
        outcome,
        main_reason,
        lost_to_competitor_ref: lost_to,
        competitors_snapshot,
        quotes: all,
    })
}

/// The text of a battle card update from the competitor's name and its
/// loss reasons and quotes.
pub fn update_text(
    name: &str,
    losses: usize,
    reasons: &[ReasonCount],
    better: &[String],
) -> String {
    let mut text = format!(
        "Battle card update for {name} (draft from {losses} loss reviews; not published)\n"
    );
    if !reasons.is_empty() {
        text.push_str("\nWhy we lose to them:\n");
        for r in reasons {
            text.push_str(&format!("- {}: {} of {losses}\n", r.reason, r.count));
        }
    }
    if !better.is_empty() {
        text.push_str("\nWhat they did better, in the reviewers' words:\n");
        for b in better {
            text.push_str(&format!("- {b}\n"));
        }
    }
    if reasons.is_empty() && better.is_empty() {
        text.push_str("\nNo loss reviews against them yet.\n");
    }
    text
}

/// A battle card update drafted from the last [`LOSS_REVIEWS`] loss reviews
/// against `competitor` that `ctx` may read. Nothing is published.
pub async fn battlecard_update_draft(
    state: &EngineState,
    ctx: &SecurityContext,
    competitor: Uuid,
) -> Result<BattlecardUpdateDraft, AppError> {
    let data = readable_data(state, ctx, "competitor", competitor)
        .await?
        .ok_or(AppError::NotFound)?;
    let name = text_of(&data, "name").unwrap_or_else(|| competitor.to_string());
    ctx.require("win_loss_review", "read")?;
    let review_entity = state
        .entities
        .load()
        .get("win_loss_review")
        .map(|m| m.entity_id)
        .ok_or(AppError::NotFound)?;
    let db = &state.base.db;
    let level = resolve_entity_access_level(
        db,
        ctx.user_id,
        review_entity,
        "win_loss_review",
        RecordAction::Read,
    )
    .await?;
    // $1 the competitor; record rules from $2.
    let predicate = rls_predicate(
        ctx,
        review_entity,
        "r",
        level,
        RecordAction::Read.share_capability(),
        2,
    );
    let rls = predicate.as_ref().map_or("", |p| p.sql.as_str());
    let sql = format!(
        "SELECT r.id FROM win_loss_review r JOIN opportunity o ON o.id = r.opportunity_ref \
         WHERE r.outcome = 'lost' \
           AND (r.is_active IS NULL OR r.is_active = true) \
           AND (o.is_active IS NULL OR o.is_active = true) \
           AND (o.lost_to_competitor_ref = $1 OR EXISTS ( \
               SELECT 1 FROM opportunity_competitor oc \
               WHERE oc.opportunity_ref = o.id AND oc.competitor_ref = $1 \
                 AND (oc.is_active IS NULL OR oc.is_active = true))) {rls} \
         ORDER BY r.created_at DESC, r.id DESC LIMIT {LOSS_REVIEWS}"
    );
    let mut query = sqlx::query_as::<_, (Uuid,)>(&sql).bind(competitor);
    if let Some(p) = &predicate {
        query = bind_rls_predicate_as(query, &p.binds);
    }
    let ids = query.fetch_all(db).await.map_err(AppError::internal)?;
    let mut losses = 0;
    let mut reasons: Vec<ReasonCount> = Vec::new();
    let mut better = Vec::new();
    for (id,) in ids {
        let Some(review) = readable_data(state, ctx, "win_loss_review", id).await? else {
            continue;
        };
        losses += 1;
        if let Some(reason) = text_of(&review, "main_reason") {
            match reasons.iter_mut().find(|r| r.reason == reason) {
                Some(r) => r.count += 1,
                None => reasons.push(ReasonCount { reason, count: 1 }),
            }
        }
        if let Some(b) = text_of(&review, "winner_did_better") {
            better.push(clip(&b));
        }
    }
    reasons.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.reason.cmp(&b.reason)));
    Ok(BattlecardUpdateDraft {
        competitor_id: competitor,
        draft: true,
        battlecard_ref: text_of(&data, "battlecard_ref"),
        losses_read: losses,
        text: update_text(&name, losses, &reasons, &better),
        reasons,
        winner_did_better: better,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deal_reasons_map_only_onto_review_choices() {
        assert_eq!(review_reason("lost", "price"), Some("price"));
        assert_eq!(review_reason("lost", "product_gap"), Some("product_fit"));
        assert_eq!(review_reason("won", "product_fit"), Some("product_fit"));
        assert_eq!(review_reason("won", "service"), Some("other"));
        assert_eq!(review_reason("lost", "no_budget"), None);
        assert_eq!(review_reason("lost", "competitor"), None);
        for (o, r) in [
            ("won", "relationship"),
            ("lost", "timing"),
            ("won", "other"),
        ] {
            let mapped = review_reason(o, r).expect("maps");
            assert!(REVIEW_REASONS.contains(&mapped));
        }
    }

    #[test]
    fn quotes_are_clipped_on_a_character_boundary() {
        let long = "ب".repeat(QUOTE_CHARS + 5);
        let clipped = clip(&long);
        assert_eq!(clipped.chars().count(), QUOTE_CHARS + 1);
        assert!(clipped.ends_with('…'));
        assert_eq!(clip("  short  "), "short");
    }

    #[test]
    fn update_text_lists_reasons_and_quotes_and_says_it_is_a_draft() {
        let reasons = vec![
            ReasonCount {
                reason: "price".into(),
                count: 3,
            },
            ReasonCount {
                reason: "timing".into(),
                count: 1,
            },
        ];
        let text = update_text("Rival", 4, &reasons, &["Faster demo".into()]);
        assert!(text.contains("not published"));
        assert!(text.contains("- price: 3 of 4"));
        assert!(text.contains("- Faster demo"));
        assert!(update_text("Rival", 0, &[], &[]).contains("No loss reviews"));
    }

    /// The drafts never write: no create, update or delete call in this file.
    #[test]
    fn drafts_never_write() {
        let source = include_str!("competitor_drafts.rs");
        let code = source.split("#[cfg(test)]").next().expect("code part");
        for write in [
            "create_record",
            "update_record",
            "delete_record",
            "INSERT ",
            "UPDATE ",
            "DELETE ",
        ] {
            assert!(!code.contains(write), "drafts must not write ({write})");
        }
    }
}
