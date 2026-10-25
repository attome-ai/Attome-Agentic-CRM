//! E13-T7: the page audit: search findings and a score for one page, the
//! topic-cluster link checks, and storing them.
//!
//! [`audit_page`] reads the page's draft blocks (columns included) and its
//! search settings and returns [`Finding`]s, each a rule, a severity, the
//! block it is about and a message key the screens translate (no English
//! text). [`score`] starts at 100 and takes 15 per error and 5 per warning.
//! [`cluster_gaps`] reports cluster pages that do not link to their topic's
//! pillar and a pillar that does not link back. [`persist_audit`] replaces
//! the page's findings and sets `seo_score` and `seo_audited_at` in one
//! transaction (`content_seo_finding`, migration 0057).
//!
//! The audit runs after a page save commits, when `content.seo_audit` is on,
//! and never blocks the save ([`audit_after_save`]). Three rules read
//! evidence other parts of the platform would gather: broken links, the
//! render time and the mobile layout flag ([`AuditInputs`]). Nothing stores
//! that evidence yet, so those rules are not applied until it is passed in.

use std::collections::HashSet;

use attome_core::EngineState;
use attome_db::DbPool;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::model::{Block, BlockKind, PageDetail};
use crate::seo::settings::{PageSeo, plain_text};

/// The fewest words a page needs not to be thin.
pub const THIN_WORDS: usize = 300;
/// The slowest render a page may have, in milliseconds.
pub const SLOW_MS: u64 = 1_000;
/// How deep columns are read for nested blocks.
const MAX_DEPTH: usize = 3;

/// How much a finding matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

/// One thing the audit found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule: &'static str,
    pub severity: Severity,
    /// The block it is about, when it is about one.
    pub block_ref: Option<String>,
    /// The catalog key of the message: `contentSeo.findings.<rule>`.
    pub message_key: String,
}

impl Finding {
    fn new(rule: &'static str, severity: Severity, block_ref: Option<String>) -> Self {
        Self {
            rule,
            severity,
            block_ref,
            message_key: format!("contentSeo.findings.{rule}"),
        }
    }
}

/// What the audit knows besides the page itself.
#[derive(Debug, Clone, Default)]
pub struct AuditInputs {
    /// The search titles of the site's other pages, lowercased.
    pub other_titles: HashSet<String>,
    /// The search descriptions of the site's other pages, lowercased.
    pub other_descriptions: HashSet<String>,
    /// The paths of the site's pages marked noindex.
    pub noindex_paths: HashSet<String>,
    /// Translations of this page that are not published, so search engines
    /// get no hreflang link for them.
    pub unpublished_translations: usize,
    /// The links on the page found broken, by block; `None` when not
    /// checked.
    pub broken_links: Option<Vec<String>>,
    /// The page's render time; `None` when not measured.
    pub render_ms: Option<u64>,
    /// Whether the page lays out on a phone; `None` when not checked.
    pub mobile_ok: Option<bool>,
}

fn filled(v: Option<&str>) -> Option<&str> {
    v.map(str::trim).filter(|s| !s.is_empty())
}

/// The page's draft blocks, the blocks inside columns included, in order.
pub fn flat_blocks(page: &PageDetail) -> Vec<Block> {
    let top: Vec<Block> = page
        .blocks_draft
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|b| serde_json::from_value::<Block>(b.clone()).ok())
                .collect()
        })
        .unwrap_or_default();
    let mut out = Vec::new();
    flatten(&top, 0, &mut out);
    out
}

fn flatten(blocks: &[Block], depth: usize, out: &mut Vec<Block>) {
    for block in blocks {
        out.push(block.clone());
        if block.kind == BlockKind::Columns && depth < MAX_DEPTH {
            for column in block
                .props
                .get("columns")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let inner: Vec<Block> = column
                    .get("blocks")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|b| serde_json::from_value::<Block>(b.clone()).ok())
                            .collect()
                    })
                    .unwrap_or_default();
                flatten(&inner, depth + 1, out);
            }
        }
    }
}

fn heading_level(block: &Block) -> u64 {
    block
        .props
        .get("level")
        .and_then(Value::as_u64)
        .filter(|l| (1..=6).contains(l))
        .unwrap_or(2)
}

/// The `href`s in a rich-text block's HTML. Pure.
pub fn links_in(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(at) = rest.find("href=") {
        rest = &rest[at + 5..];
        let quote = rest.chars().next();
        let Some(q @ ('"' | '\'')) = quote else {
            continue;
        };
        let body = &rest[1..];
        if let Some(end) = body.find(q) {
            out.push(body[..end].to_owned());
            rest = &body[end..];
        }
    }
    out
}

/// A link's site path (`/pricing`), when it points inside the site. Pure.
fn site_path(href: &str) -> Option<&str> {
    href.starts_with('/')
        .then(|| href.split(['?', '#']).next().unwrap_or(href))
        .filter(|p| !p.starts_with("//"))
}

/// The page's readable words: headings and rich text.
fn word_count(blocks: &[Block]) -> usize {
    blocks
        .iter()
        .map(|b| match b.kind {
            BlockKind::Heading => b
                .props
                .get("text")
                .and_then(Value::as_str)
                .map_or(0, |t| t.split_whitespace().count()),
            BlockKind::RichText => b
                .props
                .get("html")
                .and_then(Value::as_str)
                .map_or(0, |h| plain_text(h).split_whitespace().count()),
            _ => 0,
        })
        .sum()
}

/// The page's findings. Pure.
pub fn audit_page(page: &PageDetail, seo: &PageSeo, inputs: &AuditInputs) -> Vec<Finding> {
    let mut out = Vec::new();
    let blocks = flat_blocks(page);
    let title = filled(seo.title.as_deref()).or(filled(page.seo_title.as_deref()));
    let description =
        filled(seo.description.as_deref()).or(filled(page.seo_description.as_deref()));

    match title {
        None => out.push(Finding::new("missing_title", Severity::Warning, None)),
        Some(t) => {
            if !(30..=60).contains(&t.chars().count()) {
                out.push(Finding::new("title_length", Severity::Warning, None));
            }
            if inputs.other_titles.contains(&t.to_lowercase()) {
                out.push(Finding::new("duplicate_title", Severity::Error, None));
            }
        }
    }
    match description {
        None => out.push(Finding::new("missing_description", Severity::Warning, None)),
        Some(d) => {
            if !(70..=160).contains(&d.chars().count()) {
                out.push(Finding::new("description_length", Severity::Warning, None));
            }
            if inputs.other_descriptions.contains(&d.to_lowercase()) {
                out.push(Finding::new(
                    "duplicate_description",
                    Severity::Warning,
                    None,
                ));
            }
        }
    }

    let headings: Vec<(&Block, u64)> = blocks
        .iter()
        .filter(|b| b.kind == BlockKind::Heading)
        .map(|b| (b, heading_level(b)))
        .collect();
    let h1 = headings.iter().filter(|(_, l)| *l == 1).count();
    if h1 != 1 {
        out.push(Finding::new("single_h1", Severity::Error, None));
    }
    let mut previous = 0;
    for (block, level) in &headings {
        if previous > 0 && *level > previous + 1 {
            out.push(Finding::new(
                "heading_order",
                Severity::Warning,
                Some(block.id.to_string()),
            ));
        }
        previous = *level;
    }
    for block in blocks.iter().filter(|b| b.kind == BlockKind::Image) {
        let alt = block.props.get("alt").and_then(Value::as_str);
        if filled(alt).is_none() {
            out.push(Finding::new(
                "image_missing_alt",
                Severity::Warning,
                Some(block.id.to_string()),
            ));
        }
    }
    if word_count(&blocks) < THIN_WORDS {
        out.push(Finding::new("thin_content", Severity::Warning, None));
    }
    for block in blocks.iter().filter(|b| b.kind == BlockKind::RichText) {
        let html = block
            .props
            .get("html")
            .and_then(Value::as_str)
            .unwrap_or("");
        if links_in(html)
            .iter()
            .filter_map(|h| site_path(h))
            .any(|p| inputs.noindex_paths.contains(p))
        {
            out.push(Finding::new(
                "noindex_linked_page",
                Severity::Warning,
                Some(block.id.to_string()),
            ));
        }
    }
    if inputs.unpublished_translations > 0 {
        out.push(Finding::new("missing_hreflang", Severity::Warning, None));
    }
    for block_ref in inputs.broken_links.iter().flatten() {
        out.push(Finding::new(
            "broken_link",
            Severity::Error,
            Some(block_ref.clone()),
        ));
    }
    if inputs.render_ms.is_some_and(|ms| ms > SLOW_MS) {
        out.push(Finding::new("slow_page", Severity::Warning, None));
    }
    if inputs.mobile_ok == Some(false) {
        out.push(Finding::new("mobile_layout", Severity::Error, None));
    }
    out
}

/// The page's score: 100, less 15 per error and 5 per warning, at least 0.
/// Pure.
pub fn score(findings: &[Finding]) -> i16 {
    let lost: i32 = findings
        .iter()
        .map(|f| match f.severity {
            Severity::Error => 15,
            Severity::Warning => 5,
            Severity::Info => 0,
        })
        .sum();
    i16::try_from((100 - lost).max(0)).unwrap_or(0)
}

/// One page of a topic cluster: its path and the site paths it links to.
#[derive(Debug, Clone)]
pub struct ClusterPage {
    pub id: Uuid,
    pub path: String,
    pub links: HashSet<String>,
}

/// The link gaps of a topic: each cluster page not linking to the pillar
/// (`cluster_missing_pillar_link`, about that page) and the pillar when it
/// links to none of its cluster pages (`pillar_missing_cluster_links`).
/// Pure.
pub fn cluster_gaps(pillar: &ClusterPage, pages: &[ClusterPage]) -> Vec<(Uuid, Finding)> {
    let mut out = Vec::new();
    for page in pages.iter().filter(|p| p.id != pillar.id) {
        if !page.links.contains(&pillar.path) {
            out.push((
                page.id,
                Finding::new("cluster_missing_pillar_link", Severity::Warning, None),
            ));
        }
    }
    let cluster_paths: Vec<&str> = pages
        .iter()
        .filter(|p| p.id != pillar.id)
        .map(|p| p.path.as_str())
        .collect();
    if !cluster_paths.is_empty() && !cluster_paths.iter().any(|p| pillar.links.contains(*p)) {
        out.push((
            pillar.id,
            Finding::new("pillar_missing_cluster_links", Severity::Warning, None),
        ));
    }
    out
}

/// The site paths a page's rich text links to.
pub fn page_links(page: &PageDetail) -> HashSet<String> {
    flat_blocks(page)
        .iter()
        .filter(|b| b.kind == BlockKind::RichText)
        .filter_map(|b| b.props.get("html").and_then(Value::as_str))
        .flat_map(links_in)
        .filter_map(|h| site_path(&h).map(str::to_owned))
        .collect()
}

/// Replaces the page's findings and sets its score and audit time, in one
/// transaction.
pub async fn persist_audit(
    db: &DbPool,
    page_id: Uuid,
    findings: &[Finding],
    page_score: i16,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    sqlx::query("DELETE FROM content_seo_finding WHERE page_ref = $1")
        .bind(page_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    for f in findings {
        sqlx::query(
            "INSERT INTO content_seo_finding (page_ref, rule, severity, block_ref, detail) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(page_id)
        .bind(f.rule)
        .bind(f.severity.as_str())
        .bind(&f.block_ref)
        .bind(json!({ "message_key": f.message_key }))
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    sqlx::query("UPDATE content_page SET seo_score = $2, seo_audited_at = now() WHERE id = $1")
        .bind(page_id)
        .bind(page_score)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await
}

/// What the audit reads from the site for `page`.
pub async fn inputs_for(db: &DbPool, page: &PageDetail) -> Result<AuditInputs, AppError> {
    let others: Vec<(Option<String>, Option<String>, String, bool)> = sqlx::query_as(
        "SELECT lower(COALESCE(NULLIF(trim(seo_title), ''), title)), \
                lower(NULLIF(trim(seo_description), '')), url_path, seo_noindex \
           FROM content_page \
          WHERE content_space_id = $1 AND id <> $2 AND is_deleted = false",
    )
    .bind(page.content_space_id)
    .bind(page.id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let unpublished_translations: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM content_page \
          WHERE translation_of = $1 AND is_deleted = false AND status <> 'published'",
    )
    .bind(page.id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let mut inputs = AuditInputs {
        unpublished_translations: usize::try_from(unpublished_translations).unwrap_or(0),
        ..AuditInputs::default()
    };
    for (title, description, path, noindex) in others {
        inputs.other_titles.extend(title);
        inputs.other_descriptions.extend(description);
        if noindex {
            inputs.noindex_paths.insert(path);
        }
    }
    Ok(inputs)
}

/// E13-T9: the nightly job's name.
pub const NIGHTLY_JOB: &str = "content_seo_audit";
/// Pages audited per batch by the nightly run.
pub const NIGHTLY_BATCH: i64 = 500;

/// E13-T9: re-audits every published page, [`NIGHTLY_BATCH`] at a time,
/// when `content.seo_audit` is on for the deployment; returns how many were
/// audited. A page that fails is logged and the run goes on.
pub async fn run_nightly(state: &EngineState) -> Result<usize, AppError> {
    if !state
        .feature_flags()
        .is_on_for_deployment("content.seo_audit")
    {
        return Ok(0);
    }
    let db = &state.base.db;
    let mut after = Uuid::nil();
    let mut audited = 0;
    loop {
        let batch: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM content_page \
              WHERE is_deleted = false AND status = 'published' AND id > $1 \
              ORDER BY id LIMIT $2",
        )
        .bind(after)
        .bind(NIGHTLY_BATCH)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let Some(last) = batch.last().copied() else {
            break;
        };
        for page in batch {
            match crate::seo::site::audit_now(db, page).await {
                Ok(_) => audited += 1,
                Err(error) => {
                    tracing::warn!(%page, %error, "nightly seo audit: page skipped");
                }
            }
        }
        after = last;
    }
    Ok(audited)
}

/// Audits a page after its save committed, when `content.seo_audit` is on
/// for `ctx`; a failure is logged and never undoes the save.
pub async fn audit_after_save(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    page: &PageDetail,
) {
    if !state.feature_flags().is_on("content.seo_audit", ctx).await {
        return;
    }
    let db = &state.base.db;
    let run = async {
        let (seo, _) = crate::seo::settings::get_page_seo(db, page.id).await?;
        let inputs = inputs_for(db, page).await?;
        let findings = audit_page(page, &seo, &inputs);
        persist_audit(db, page.id, &findings, score(&findings)).await
    };
    if let Err(e) = run.await {
        tracing::warn!(page = %page.id, error = %e, "content page audit failed; the save stands");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn page(blocks: Value) -> PageDetail {
        serde_json::from_value(json!({
            "id": Uuid::nil(),
            "parent_page_id": null,
            "content_space_id": Uuid::nil(),
            "title": "Pricing",
            "url_path": "/pricing",
            "status": "draft",
            "template_id": null,
            "blocks_draft": blocks,
            "blocks_published": null,
            "seo_title": null,
            "seo_description": null,
            "published_at": null,
            "publish_at": null,
            "unpublish_at": null,
            "row_version": 1,
            "created_at": Utc::now(),
            "updated_at": Utc::now(),
        }))
        .expect("a page")
    }

    fn block(kind: &str, props: Value) -> Value {
        json!({"id": Uuid::now_v7(), "kind": kind, "props": props})
    }

    fn good_seo() -> PageSeo {
        PageSeo {
            title: Some("Attome pricing for teams of every size".into()),
            description: Some(
                "Plans and prices for Attome, from one server on your own machine to many \
                 nodes for a large organisation."
                    .into(),
            ),
            ..PageSeo::default()
        }
    }

    fn words(n: usize) -> String {
        format!("<p>{}</p>", vec!["word"; n].join(" "))
    }

    fn rules(findings: &[Finding]) -> Vec<&'static str> {
        findings.iter().map(|f| f.rule).collect()
    }

    fn clean_page() -> PageDetail {
        page(json!([
            block("heading", json!({"text": "Pricing", "level": 1})),
            block("rich_text", json!({"html": words(320)})),
        ]))
    }

    #[test]
    fn rule_clean_page_has_no_findings() {
        let found = audit_page(&clean_page(), &good_seo(), &AuditInputs::default());
        assert!(found.is_empty(), "{found:?}");
        assert_eq!(score(&found), 100);
    }

    #[test]
    fn rule_missing_title() {
        let seo = PageSeo {
            title: None,
            ..good_seo()
        };
        let found = audit_page(&clean_page(), &seo, &AuditInputs::default());
        assert_eq!(rules(&found), vec!["missing_title"]);
    }

    #[test]
    fn rule_missing_description() {
        let seo = PageSeo {
            description: Some("  ".into()),
            ..good_seo()
        };
        let found = audit_page(&clean_page(), &seo, &AuditInputs::default());
        assert_eq!(rules(&found), vec!["missing_description"]);
    }

    #[test]
    fn rule_title_length() {
        let seo = PageSeo {
            title: Some("Pricing".into()),
            ..good_seo()
        };
        let found = audit_page(&clean_page(), &seo, &AuditInputs::default());
        assert_eq!(rules(&found), vec!["title_length"]);
    }

    #[test]
    fn rule_description_length() {
        let seo = PageSeo {
            description: Some("Too short.".into()),
            ..good_seo()
        };
        let found = audit_page(&clean_page(), &seo, &AuditInputs::default());
        assert_eq!(rules(&found), vec!["description_length"]);
    }

    #[test]
    fn rule_duplicate_title() {
        let inputs = AuditInputs {
            other_titles: ["attome pricing for teams of every size".to_owned()].into(),
            ..AuditInputs::default()
        };
        let found = audit_page(&clean_page(), &good_seo(), &inputs);
        assert_eq!(rules(&found), vec!["duplicate_title"]);
        assert_eq!(score(&found), 85);
    }

    #[test]
    fn rule_duplicate_description() {
        let description = good_seo().description.unwrap().to_lowercase();
        let inputs = AuditInputs {
            other_descriptions: [description].into(),
            ..AuditInputs::default()
        };
        let found = audit_page(&clean_page(), &good_seo(), &inputs);
        assert_eq!(rules(&found), vec!["duplicate_description"]);
    }

    #[test]
    fn rule_single_h1() {
        let p = page(json!([
            block("heading", json!({"text": "A", "level": 1})),
            block("heading", json!({"text": "B", "level": 1})),
            block("rich_text", json!({"html": words(320)})),
        ]));
        let found = audit_page(&p, &good_seo(), &AuditInputs::default());
        assert_eq!(rules(&found), vec!["single_h1"]);
    }

    #[test]
    fn rule_heading_order() {
        let p = page(json!([
            block("heading", json!({"text": "A", "level": 1})),
            block("heading", json!({"text": "B", "level": 3})),
            block("rich_text", json!({"html": words(320)})),
        ]));
        let found = audit_page(&p, &good_seo(), &AuditInputs::default());
        assert_eq!(rules(&found), vec!["heading_order"]);
        assert!(found[0].block_ref.is_some());
    }

    #[test]
    fn rule_image_missing_alt() {
        let p = page(json!([
            block("heading", json!({"text": "A", "level": 1})),
            block("image", json!({"src": "https://x/a.png"})),
            block("rich_text", json!({"html": words(320)})),
        ]));
        let found = audit_page(&p, &good_seo(), &AuditInputs::default());
        assert_eq!(rules(&found), vec!["image_missing_alt"]);
    }

    #[test]
    fn rule_thin_content() {
        let p = page(json!([
            block("heading", json!({"text": "A", "level": 1})),
            block("rich_text", json!({"html": words(40)})),
        ]));
        let found = audit_page(&p, &good_seo(), &AuditInputs::default());
        assert_eq!(rules(&found), vec!["thin_content"]);
    }

    #[test]
    fn rule_noindex_linked_page() {
        let p = page(json!([
            block("heading", json!({"text": "A", "level": 1})),
            block(
                "rich_text",
                json!({"html": format!("{}<a href=\"/hidden?x=1\">x</a>", words(320))})
            ),
        ]));
        let inputs = AuditInputs {
            noindex_paths: ["/hidden".to_owned()].into(),
            ..AuditInputs::default()
        };
        let found = audit_page(&p, &good_seo(), &inputs);
        assert_eq!(rules(&found), vec!["noindex_linked_page"]);
    }

    #[test]
    fn rule_missing_hreflang() {
        let inputs = AuditInputs {
            unpublished_translations: 1,
            ..AuditInputs::default()
        };
        let found = audit_page(&clean_page(), &good_seo(), &inputs);
        assert_eq!(rules(&found), vec!["missing_hreflang"]);
    }

    #[test]
    fn rule_broken_link() {
        let inputs = AuditInputs {
            broken_links: Some(vec!["b1".into()]),
            ..AuditInputs::default()
        };
        let found = audit_page(&clean_page(), &good_seo(), &inputs);
        assert_eq!(rules(&found), vec!["broken_link"]);
    }

    #[test]
    fn rule_slow_page() {
        let inputs = AuditInputs {
            render_ms: Some(1_500),
            ..AuditInputs::default()
        };
        let found = audit_page(&clean_page(), &good_seo(), &inputs);
        assert_eq!(rules(&found), vec!["slow_page"]);
    }

    #[test]
    fn rule_mobile_layout() {
        let inputs = AuditInputs {
            mobile_ok: Some(false),
            ..AuditInputs::default()
        };
        let found = audit_page(&clean_page(), &good_seo(), &inputs);
        assert_eq!(rules(&found), vec!["mobile_layout"]);
    }

    #[test]
    fn rule_score_floors_at_zero() {
        let many: Vec<Finding> = (0..10)
            .map(|_| Finding::new("duplicate_title", Severity::Error, None))
            .collect();
        assert_eq!(score(&many), 0);
    }

    #[test]
    fn rule_cluster_gaps() {
        let pillar = ClusterPage {
            id: Uuid::from_u128(1),
            path: "/guide".into(),
            links: HashSet::new(),
        };
        let linked = ClusterPage {
            id: Uuid::from_u128(2),
            path: "/guide/a".into(),
            links: ["/guide".to_owned()].into(),
        };
        let unlinked = ClusterPage {
            id: Uuid::from_u128(3),
            path: "/guide/b".into(),
            links: HashSet::new(),
        };
        let gaps = cluster_gaps(&pillar, &[pillar.clone(), linked, unlinked]);
        let found: Vec<(Uuid, &str)> = gaps.iter().map(|(id, f)| (*id, f.rule)).collect();
        assert_eq!(
            found,
            vec![
                (Uuid::from_u128(3), "cluster_missing_pillar_link"),
                (Uuid::from_u128(1), "pillar_missing_cluster_links"),
            ]
        );
    }

    #[test]
    fn rule_links_are_read_from_rich_text() {
        assert_eq!(
            links_in("<a href=\"/a\">a</a> <a href='https://x/b'>b</a>"),
            vec!["/a".to_owned(), "https://x/b".to_owned()]
        );
        assert_eq!(site_path("/a?b=1#c"), Some("/a"));
        assert_eq!(site_path("//evil"), None);
    }
}
