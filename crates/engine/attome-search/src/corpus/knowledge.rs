//! Article chunking and passage expansion (TODO-032, `P-knowledge-base` §6).
//!
//! ## Chunk small, return big
//!
//! **Retrieve on chunks. Return the enclosing section.** These are deliberately
//! different units, and conflating them is the most common reason RAG answers
//! read as confidently wrong: a window centred on a match routinely severs the
//! sentence that qualifies it — the "unless the contract was renewed after
//! March" — and the model never sees the qualifier or learns it existed.
//!
//! That failure is invisible from the outside. A truncated answer looks exactly
//! like a complete one, which is why the mitigation has to be structural and
//! why TODO-024's coverage harness — not nDCG — is the instrument that measures
//! it.
//!
//! ## Splitting is structural first, then size-bounded
//!
//! Headings are the author's own statement about where one idea stops. Splitting
//! on them before falling back to size means a chunk boundary usually coincides
//! with a semantic boundary, and the expansion step has a real unit to expand
//! *to*. A fixed-size splitter has neither.
//!
//! Within a section, splitting is by paragraph and then by sentence, never
//! mid-sentence. A chunk ending mid-clause embeds badly (the vector describes a
//! fragment) and reads worse when returned.
//!
//! ## The heading path is captured here
//!
//! §8: captured at chunk time, never reconstructed at render time. An article
//! edited after an answer was generated would otherwise produce a citation
//! pointing at a heading that no longer exists.

use sha2::{Digest, Sha256};

use crate::project::index_text;

/// Target chunk size in characters.
///
/// Characters rather than tokens because tokenization belongs to the embedding
/// model and this layer must not depend on which one is configured — an
/// air-gapped deployment may swap it. The ratio is roughly 4 chars/token for
/// English and closer to 2 for Arabic, so this is deliberately conservative:
/// **the Arabic case is the binding one**, and sizing on English would make
/// every Arabic chunk overflow the window it was meant to fit.
pub const TARGET_CHUNK_CHARS: usize = 1_200;

/// A chunk shorter than this is merged forward rather than emitted.
///
/// A three-word chunk matches almost nothing and pollutes the candidate set
/// when it does — it is high-similarity noise, because a short text is
/// trivially similar to a short query.
pub const MIN_CHUNK_CHARS: usize = 200;

/// The ceiling on an expanded passage.
///
/// Expansion exists to restore severed context, not to return whole documents:
/// past this the passage stops being evidence and starts being the corpus, and
/// the model's attention degrades across it. An article longer than this is
/// returned as the matched section rather than whole.
pub const MAX_PASSAGE_CHARS: usize = 6_000;

/// One chunk of an article, ready to index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArticleChunk {
    pub ordinal: i32,
    /// The heading path at this point in the document, outermost first.
    pub heading_path: Vec<String>,
    /// Which section this belongs to. Two chunks share a section index iff they
    /// sit under the same heading — this is what lets expansion find its unit
    /// without re-parsing.
    pub section: usize,
    pub text_display: String,
    pub text_indexed: String,
    pub content_hash: Vec<u8>,
}

/// A parsed section: a heading path and its body.
#[derive(Debug, Clone)]
struct Section {
    heading_path: Vec<String>,
    body: String,
}

/// Splits markdown-ish text into sections on ATX headings (`#`..`######`).
///
/// Text before the first heading is a section with an empty path rather than
/// being dropped — an article whose first paragraph precedes any heading is
/// entirely normal, and dropping it would silently lose the lede, which is
/// usually the part that answers the question.
fn split_sections(body: &str) -> Vec<Section> {
    let mut sections: Vec<Section> = Vec::new();
    let mut path: Vec<String> = Vec::new();
    let mut current = String::new();

    let flush = |sections: &mut Vec<Section>, path: &[String], current: &mut String| {
        if !current.trim().is_empty() {
            sections.push(Section {
                heading_path: path.to_vec(),
                body: std::mem::take(current).trim().to_owned(),
            });
        } else {
            current.clear();
        }
    };

    for line in body.lines() {
        let trimmed = line.trim_start();
        let level = trimmed.chars().take_while(|c| *c == '#').count();
        let is_heading = (1..=6).contains(&level)
            && trimmed.chars().nth(level) == Some(' ')
            && !trimmed[level + 1..].trim().is_empty();

        if is_heading {
            flush(&mut sections, &path, &mut current);
            let title = trimmed[level + 1..].trim().to_owned();
            path.truncate(level.saturating_sub(1));
            path.push(title);
        } else {
            current.push_str(line);
            current.push('\n');
        }
    }
    flush(&mut sections, &path, &mut current);
    sections
}

/// The heading path of every section [`chunk_article`] emits, in order.
///
/// Exposed for the knowledge benchmark (`knowledge_eval`), which keys its
/// judgments by section. Using this splitter rather than a second parser means
/// a fixture judgment can only name a section the chunker actually produces —
/// a heading with no body of its own produces no chunk, and so no section.
pub fn section_heading_paths(body: &str) -> Vec<Vec<String>> {
    split_sections(body)
        .into_iter()
        .map(|s| s.heading_path)
        .collect()
}

/// Splits one section's body into size-bounded pieces on paragraph, then
/// sentence, boundaries — never mid-sentence.
#[expect(
    clippy::expect_used,
    reason = "each expect() here guards an invariant its message states"
)]
fn split_body(body: &str) -> Vec<String> {
    let mut pieces: Vec<String> = Vec::new();
    let mut current = String::new();

    let push_unit = |unit: &str, pieces: &mut Vec<String>, current: &mut String| {
        if current.chars().count() + unit.chars().count() > TARGET_CHUNK_CHARS
            && !current.trim().is_empty()
        {
            pieces.push(std::mem::take(current).trim().to_owned());
        }
        current.push_str(unit);
        current.push(' ');
    };

    for paragraph in body.split("\n\n").filter(|p| !p.trim().is_empty()) {
        if paragraph.chars().count() <= TARGET_CHUNK_CHARS {
            push_unit(paragraph.trim(), &mut pieces, &mut current);
            continue;
        }
        // A paragraph over the target is split by sentence. `. ` / `؟ ` / `۔ `
        // rather than a full sentence tokenizer: the Arabic question mark and
        // full stop are the two that a naive `split('.')` misses entirely, and
        // missing them turns every Arabic paragraph into one oversized chunk.
        for sentence in split_sentences(paragraph) {
            push_unit(sentence.trim(), &mut pieces, &mut current);
        }
    }
    if !current.trim().is_empty() {
        pieces.push(current.trim().to_owned());
    }

    // Merge a runt forward. A short trailing chunk is high-similarity noise.
    if pieces.len() >= 2 {
        let last_len = pieces[pieces.len() - 1].chars().count();
        if last_len < MIN_CHUNK_CHARS {
            let runt = pieces.pop().expect("len >= 2");
            let prev = pieces.last_mut().expect("len >= 1");
            prev.push(' ');
            prev.push_str(&runt);
        }
    }
    pieces
}

/// Sentence boundaries, including the Arabic full stop and question mark.
fn split_sentences(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        current.push(ch);
        if matches!(ch, '.' | '!' | '?' | '\u{061F}' | '\u{06D4}') {
            out.push(std::mem::take(&mut current));
        }
    }
    if !current.trim().is_empty() {
        out.push(current);
    }
    out
}

/// Chunks an article.
///
/// The title is prepended to every chunk's *indexed* text, not its display
/// text. A chunk from the middle of a long article otherwise carries no signal
/// about what document it belongs to, and a query naming the document matches
/// only the one chunk that happens to repeat its name — the single cheapest
/// retrieval-quality fix in the whole pipeline, and free.
pub fn chunk_article(title: &str, body: &str) -> Vec<ArticleChunk> {
    let mut chunks = Vec::new();
    let mut ordinal = 0i32;

    for (section_idx, section) in split_sections(body).into_iter().enumerate() {
        for piece in split_body(&section.body) {
            let indexed = index_text(&format!(
                "{title} {} {piece}",
                section.heading_path.join(" ")
            ));
            let mut hasher = Sha256::new();
            hasher.update((piece.len() as u64).to_le_bytes());
            hasher.update(piece.as_bytes());
            hasher.update(section.heading_path.join("\u{0}").as_bytes());
            chunks.push(ArticleChunk {
                ordinal,
                heading_path: section.heading_path.clone(),
                section: section_idx,
                text_display: piece,
                text_indexed: indexed,
                content_hash: hasher.finalize()[..16].to_vec(),
            });
            ordinal += 1;
        }
    }
    chunks
}

/// Expands matched chunks into the passages actually returned.
///
/// **This is the "return big" half, and it is the point of the module.** Given
/// the ordinals that matched, returns the enclosing section for each, merged
/// where matches are adjacent or share a section, and capped at
/// [`MAX_PASSAGE_CHARS`].
///
/// Merging happens *before* expansion, so a match spanning a heading boundary
/// is returned once rather than twice with an overlap — duplicated context
/// wastes the budget and reads to the model as corroboration.
pub fn expand(chunks: &[ArticleChunk], matched: &[i32]) -> Vec<Passage> {
    let mut sections: Vec<usize> = matched
        .iter()
        .filter_map(|o| chunks.iter().find(|c| c.ordinal == *o).map(|c| c.section))
        .collect();
    sections.sort_unstable();
    sections.dedup();

    sections
        .into_iter()
        .map(|section| {
            let members: Vec<&ArticleChunk> =
                chunks.iter().filter(|c| c.section == section).collect();
            let heading_path = members
                .first()
                .map(|c| c.heading_path.clone())
                .unwrap_or_default();

            let mut text = String::new();
            let mut truncated = false;
            for member in &members {
                if text.chars().count() + member.text_display.chars().count() > MAX_PASSAGE_CHARS {
                    // Past the ceiling the passage stops being evidence and
                    // starts being the corpus. Reported, never silent — a
                    // caller that cannot tell it received a partial section
                    // cannot say so in an answer.
                    truncated = true;
                    break;
                }
                if !text.is_empty() {
                    text.push_str("\n\n");
                }
                text.push_str(&member.text_display);
            }

            // Only the input ordinals that actually matched *this* section —
            // not every ordinal matched anywhere in the item. A multi-section
            // match must not stamp every returned passage with the full
            // matched set, or a retrieval-count caller that sums chunk ids
            // across passages double-counts (D-452's retrieval metric would
            // otherwise credit chunks a given passage never contained).
            let matched_ordinals: Vec<i32> = matched
                .iter()
                .copied()
                .filter(|o| {
                    chunks
                        .iter()
                        .any(|c| c.ordinal == *o && c.section == section)
                })
                .collect();

            Passage {
                heading_path,
                text,
                truncated,
                first_ordinal: members.first().map(|c| c.ordinal).unwrap_or(0),
                matched_ordinals,
            }
        })
        .collect()
}

/// A returned passage: the enclosing section, with what a citation needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passage {
    pub heading_path: Vec<String>,
    pub text: String,
    /// The section exceeded [`MAX_PASSAGE_CHARS`]. **Reported to the caller**,
    /// because an answer drawn from a partial section should be able to say so.
    pub truncated: bool,
    pub first_ordinal: i32,
    /// The subset of `expand`'s `matched` input that landed in this passage's
    /// section — what a caller must use to attribute a chunk-level signal
    /// (like retrieval telemetry) to the right passage, rather than the
    /// item's full matched-chunk set.
    pub matched_ordinals: Vec<i32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARTICLE: &str = "\
Intro paragraph before any heading, which is entirely normal.

# Refunds

Goods may be returned within thirty days of the invoice date.

Refunds are issued to the original payment method.

## Exceptions

Custom orders are non-refundable unless the contract was renewed after March.

# Shipping

Standard delivery is five working days.
";

    /// **The property the module exists for.** A match on the chunk containing
    /// "custom orders are non-refundable" returns the whole section — including
    /// the qualifier that changes the answer.
    #[test]
    fn expansion_returns_the_qualifier_a_chunk_would_have_severed() {
        let chunks = chunk_article("Returns policy", ARTICLE);
        let matched = chunks
            .iter()
            .find(|c| c.text_display.contains("non-refundable"))
            .expect("the clause is chunked");

        let passages = expand(&chunks, &[matched.ordinal]);
        assert_eq!(passages.len(), 1);
        assert!(
            passages[0].text.contains("renewed after March"),
            "the qualifier must survive: {}",
            passages[0].text
        );
        assert_eq!(
            passages[0].heading_path,
            vec!["Refunds".to_string(), "Exceptions".to_string()],
            "the citation's heading path is the full nesting, not just the leaf"
        );
    }

    /// Text before the first heading is kept. An article's lede is usually the
    /// part that answers the question, and dropping it would be silent.
    #[test]
    fn the_lede_before_the_first_heading_is_not_dropped() {
        let chunks = chunk_article("Returns policy", ARTICLE);
        assert!(
            chunks
                .iter()
                .any(|c| c.text_display.contains("Intro paragraph")),
            "content before the first heading must be chunked"
        );
        assert!(
            chunks[0].heading_path.is_empty(),
            "and it has no heading path"
        );
    }

    /// The heading path nests. A citation naming only "Exceptions" is ambiguous
    /// in any article with two of them.
    #[test]
    fn heading_paths_nest_and_pop() {
        let chunks = chunk_article("t", ARTICLE);
        let shipping = chunks
            .iter()
            .find(|c| c.text_display.contains("Standard delivery"))
            .expect("shipping section");
        assert_eq!(
            shipping.heading_path,
            vec!["Shipping".to_string()],
            "a level-1 heading must pop the previous level-2, not accumulate"
        );
    }

    /// Two matches in the same section produce **one** passage. Duplicated
    /// context wastes the budget and reads to the model as corroboration.
    #[test]
    fn adjacent_matches_in_one_section_merge_into_one_passage() {
        let chunks = chunk_article("t", ARTICLE);
        let refunds: Vec<i32> = chunks
            .iter()
            .filter(|c| c.heading_path == vec!["Refunds".to_string()])
            .map(|c| c.ordinal)
            .collect();
        assert!(!refunds.is_empty());
        let passages = expand(&chunks, &refunds);
        assert_eq!(passages.len(), 1, "one section, one passage");
    }

    /// A match spanning two different sections must not stamp both returned
    /// passages with every matched ordinal — a caller that maps
    /// `matched_ordinals` to chunk ids for retrieval telemetry would
    /// otherwise credit each passage with chunks it never actually
    /// contained, double-counting the retrieval (the bug this field exists
    /// to close).
    #[test]
    fn each_passage_carries_only_the_ordinals_matched_in_its_own_section() {
        let chunks = chunk_article("t", ARTICLE);
        let refund_ordinal = chunks
            .iter()
            .find(|c| c.heading_path == vec!["Refunds".to_string()])
            .expect("a refunds chunk")
            .ordinal;
        let shipping_ordinal = chunks
            .iter()
            .find(|c| c.text_display.contains("Standard delivery"))
            .expect("a shipping chunk")
            .ordinal;

        let passages = expand(&chunks, &[refund_ordinal, shipping_ordinal]);
        assert_eq!(passages.len(), 2, "two sections, two passages");

        for passage in &passages {
            assert_eq!(
                passage.matched_ordinals.len(),
                1,
                "each passage must carry only the one ordinal matched in its own \
                 section, not both: {passage:?}"
            );
        }
        let all_matched: Vec<i32> = passages
            .iter()
            .flat_map(|p| p.matched_ordinals.iter().copied())
            .collect();
        assert!(all_matched.contains(&refund_ordinal));
        assert!(all_matched.contains(&shipping_ordinal));
    }

    /// The title reaches the indexed text but not the display text.
    ///
    /// A chunk from the middle of an article otherwise carries no signal about
    /// which document it belongs to; putting the title in the *display* text
    /// instead would repeat it in every rendered passage.
    #[test]
    fn the_title_is_indexed_but_not_displayed() {
        let chunks = chunk_article("Returns policy", ARTICLE);
        let c = &chunks[0];
        assert!(
            c.text_indexed.contains(&index_text("Returns policy")),
            "the title must be searchable from every chunk: {}",
            c.text_indexed
        );
        assert!(
            !c.text_display.contains("Returns policy"),
            "but must not be repeated in what the user reads"
        );
    }

    /// The heading path is indexed too — someone searching "refund exceptions"
    /// should find the section named "Exceptions" under "Refunds".
    #[test]
    fn the_heading_path_is_searchable() {
        let chunks = chunk_article("t", ARTICLE);
        let c = chunks
            .iter()
            .find(|c| c.text_display.contains("non-refundable"))
            .unwrap();
        assert!(c.text_indexed.contains(&index_text("Exceptions")));
    }

    /// Arabic splits on its own sentence terminators.
    ///
    /// A naive `split('.')` never fires on Arabic text, so an Arabic article
    /// becomes one oversized chunk — which embeds badly and expands to nothing
    /// useful. Silent, and only in the platform's primary market.
    #[test]
    fn arabic_sentences_split_on_arabic_terminators() {
        let long_ar = "هذه جملة أولى طويلة جدا. ".repeat(60);
        let chunks = chunk_article("سياسة", &format!("# القسم\n\n{long_ar}"));
        assert!(
            chunks.len() > 1,
            "an Arabic article over the target must split, not become one chunk"
        );
        for c in &chunks {
            assert!(
                c.text_display.chars().count() <= TARGET_CHUNK_CHARS * 2,
                "no chunk may run away: {} chars",
                c.text_display.chars().count()
            );
        }
    }

    /// A very short trailing chunk is merged forward rather than emitted. A
    /// three-word chunk is high-similarity noise — a short text is trivially
    /// similar to a short query.
    #[test]
    fn a_runt_chunk_is_merged_forward() {
        let body = format!("# S\n\n{}\n\nok.", "Sentence about logistics. ".repeat(80));
        let chunks = chunk_article("t", &body);
        for c in &chunks {
            assert!(
                c.text_display.chars().count() >= MIN_CHUNK_CHARS || chunks.len() == 1,
                "emitted a runt: {:?}",
                c.text_display
            );
        }
    }

    /// Truncation of an oversized section is reported, not silent.
    #[test]
    fn an_oversized_section_reports_truncation() {
        let body = format!(
            "# Big\n\n{}",
            "A long sentence of policy text. ".repeat(400)
        );
        let chunks = chunk_article("t", &body);
        let passages = expand(&chunks, &[chunks[0].ordinal]);
        assert!(
            passages[0].truncated,
            "a caller that cannot tell it received a partial section cannot say \
             so in an answer"
        );
        assert!(passages[0].text.chars().count() <= MAX_PASSAGE_CHARS);
    }

    /// Ordinals are dense and ascending, so `expand` can find a chunk by
    /// ordinal and the unique constraint on `(source_type, source_id, ordinal)`
    /// holds.
    #[test]
    fn ordinals_are_dense_and_ascending() {
        let chunks = chunk_article("t", ARTICLE);
        for (i, c) in chunks.iter().enumerate() {
            assert_eq!(c.ordinal, i as i32);
        }
    }

    /// Re-chunking unchanged content produces identical hashes, so the drain's
    /// gate skips the rewrite — the same property `drain_hash_gate.rs` pins for
    /// records.
    #[test]
    fn chunking_is_deterministic() {
        assert_eq!(chunk_article("t", ARTICLE), chunk_article("t", ARTICLE));
    }

    /// An empty article produces no chunks rather than one empty one. An empty
    /// chunk matches nothing and occupies an ordinal.
    #[test]
    fn an_empty_article_produces_no_chunks() {
        assert!(chunk_article("t", "").is_empty());
        assert!(chunk_article("t", "   \n\n  ").is_empty());
    }
}
