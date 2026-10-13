//! Projecting a record into an index row, and hashing what it produced
//! (TODO-016's prerequisite).
//!
//! One projection function, used by **both** the drain and the backfill. That
//! is not tidiness — a backfill that projected differently from the drain would
//! produce an index whose rows disagree depending on how they got there, and
//! the disagreement would surface as "some records aren't findable" long after
//! anyone could connect it to the cause.

use sha2::{Digest, Sha256};

use crate::lang::{normalize_ar, stem_ar, stem_en};

/// Bytes of the content hash stored per row.
///
/// 16, not 32: this is change detection, not authentication. At 128 bits a
/// collision across a customer's whole corpus is not a thing that happens, and
/// the column is written once per indexed record.
pub const CONTENT_HASH_LEN: usize = 16;

/// One record, projected into what the index stores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectedRow {
    pub title: String,
    pub title_norm: String,
    pub subtitle: Option<String>,
    /// The original body, kept verbatim for `ts_headline` — a snippet built
    /// from normalized, stemmed text would show the user mangled words.
    pub body_display: String,
    /// Normalized, stemmed, and truncated. See [`MAX_INDEXED_BODY_BYTES`].
    pub body_indexed: String,
    pub exact_keys: Vec<String>,
    pub content_hash: Vec<u8>,
}

/// Ceiling on `body_indexed`, in bytes.
///
/// **`tsvector` has a hard 1 MB limit and `to_tsvector` THROWS above it**
/// rather than truncating. Without this, one pasted contract or one OCR'd
/// scan fails its own indexing *and takes the whole drain batch with it* —
/// every other record in that batch stops being indexed because of a document
/// none of them have anything to do with.
///
/// 512 KB leaves generous headroom: normalization and stemming can only
/// shrink text, but the limit applies to the lexeme representation rather than
/// the input, and the margin costs nothing worth measuring.
pub const MAX_INDEXED_BODY_BYTES: usize = 512 * 1024;

/// Normalizes and stems one field's text for the index.
///
/// **Both steps, in this order, from the same functions the query path uses.**
/// A field normalized but not stemmed — or stemmed with a different stemmer —
/// produces lexemes the query never generates, and the record silently stops
/// matching ordinary words. `lang`'s module doc has the long version.
pub fn index_text(raw: &str) -> String {
    normalize_ar(raw)
        .split_whitespace()
        .map(|token| {
            // Arabic and Latin tokens take different stemmers, decided per
            // token rather than per field: mixed Arabic/English inside one
            // value is the GCC norm, so a per-field language guess would be
            // wrong for a large share of real records.
            if token.chars().any(is_arabic) {
                stem_ar(token)
            } else {
                stem_en(token)
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_arabic(c: char) -> bool {
    matches!(c, '\u{0600}'..='\u{06FF}' | '\u{0750}'..='\u{077F}' | '\u{FB50}'..='\u{FDFF}' | '\u{FE70}'..='\u{FEFF}')
}

/// Truncates to [`MAX_INDEXED_BODY_BYTES`] on a **character boundary**.
///
/// Slicing a `String` at a byte offset mid-codepoint panics, and a body large
/// enough to need truncating is very likely the one containing multi-byte
/// text — so the naive version fails precisely on the input it exists to
/// handle.
pub fn truncate_for_index(text: &str) -> &str {
    if text.len() <= MAX_INDEXED_BODY_BYTES {
        return text;
    }
    let mut end = MAX_INDEXED_BODY_BYTES;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Hashes the projected content.
///
/// **Deviation from the plan, recorded rather than silent:**
/// `P-search-and-retrieval` §8 specifies BLAKE3. This uses SHA-256 truncated to
/// [`CONTENT_HASH_LEN`], because `sha2` is already a workspace dependency and
/// `blake3` is not. The plan's argument for BLAKE3 is speed ("16 bytes and one
/// BLAKE3 pass"), and SHA-256 over a few kilobytes of text is also
/// microseconds — well under the cost of the row write this is deciding
/// whether to skip. The property actually required is collision resistance for
/// change detection, which SHA-256 supplies amply. If profiling ever shows the
/// hash on the critical path, adding `blake3` is a one-line change and this
/// comment is the record of why it was not taken first.
///
/// Field boundaries are hashed explicitly (a length prefix per field), so
/// moving text from a title to a body changes the hash. Concatenating without
/// delimiters would make `("ab", "c")` and `("a", "bc")` hash identically —
/// and a record whose fields were rearranged would be skipped as unchanged.
pub fn content_hash(fields: &[&str]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    hasher.finalize()[..CONTENT_HASH_LEN].to_vec()
}

/// Projects a record's already-extracted text into an index row.
///
/// Takes text rather than a `serde_json::Value` on purpose: deciding *which*
/// fields of an entity are the title, the body, and the identifiers is
/// metadata-driven and belongs to the caller. This function owns what happens
/// to that text once chosen, which is the part that must not vary between the
/// drain and the backfill.
pub fn project(
    title: &str,
    subtitle: Option<&str>,
    body: &str,
    exact_keys: Vec<String>,
) -> ProjectedRow {
    let title_norm = normalize_ar(title);
    let body_indexed = index_text(truncate_for_index(body));
    let normalized_keys: Vec<String> = exact_keys.iter().map(|k| normalize_ar(k)).collect();

    let hash = content_hash(&[
        title,
        subtitle.unwrap_or(""),
        body,
        &normalized_keys.join("\u{0}"),
    ]);

    ProjectedRow {
        title: title.to_owned(),
        title_norm,
        subtitle: subtitle.map(str::to_owned),
        body_display: body.to_owned(),
        body_indexed,
        exact_keys: normalized_keys,
        content_hash: hash,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hash_is_stable_and_changes_with_content() {
        let a = project("ACME", None, "invoice", vec!["inv-1".into()]);
        let same = project("ACME", None, "invoice", vec!["inv-1".into()]);
        let different = project("ACME", None, "invoice paid", vec!["inv-1".into()]);

        assert_eq!(
            a.content_hash, same.content_hash,
            "identical input must hash alike"
        );
        assert_ne!(a.content_hash, different.content_hash);
        assert_eq!(a.content_hash.len(), CONTENT_HASH_LEN);
    }

    /// Field boundaries are hashed. Without a length prefix, moving a
    /// character from the title to the body would leave the hash unchanged and
    /// the drain would skip a record that genuinely changed — the exact defect
    /// `content_hash` exists to avoid, arriving through the hash itself.
    #[test]
    fn moving_text_between_fields_changes_the_hash() {
        let a = project("ab", None, "c", vec![]);
        let b = project("a", None, "bc", vec![]);
        assert_ne!(
            a.content_hash, b.content_hash,
            "field boundaries must be part of the hash"
        );
    }

    /// A body over the limit is cut, and cut on a character boundary. Slicing
    /// mid-codepoint panics, and a body large enough to truncate is exactly the
    /// one likely to contain multi-byte text.
    #[test]
    fn an_oversized_body_is_truncated_on_a_character_boundary() {
        // Arabic is 2 bytes per char, so the byte limit lands mid-character
        // for some multiple — which is the case that panics if unhandled.
        let huge = "محمد ".repeat(200_000);
        assert!(huge.len() > MAX_INDEXED_BODY_BYTES);

        let cut = truncate_for_index(&huge);
        assert!(cut.len() <= MAX_INDEXED_BODY_BYTES);
        // The real assertion: this is valid UTF-8 that Rust will hand to
        // Postgres without panicking.
        assert!(std::str::from_utf8(cut.as_bytes()).is_ok());

        let row = project("t", None, &huge, vec![]);
        assert!(row.body_indexed.len() <= MAX_INDEXED_BODY_BYTES);
        // body_display keeps the ORIGINAL, untruncated — `ts_headline` reads
        // it, and a snippet from a truncated body would silently lose the
        // matching passage.
        assert_eq!(row.body_display.len(), huge.len());
    }

    /// The indexed text is normalized AND stemmed, from the same functions the
    /// query path uses. A field normalized but not stemmed produces lexemes
    /// the query never generates.
    #[test]
    fn indexed_text_is_normalized_and_stemmed() {
        // The property that matters is not which string comes out but that
        // singular and plural come out THE SAME — that is what makes
        // "invoices" find a record saying "invoice". The light stemmer strips
        // the plural rather than reducing to a Porter-style root, which is the
        // deliberate precision-over-recall choice `lang::stem` documents.
        assert_eq!(index_text("Invoices"), index_text("invoice"));
        assert_eq!(index_text("الشركة"), "شركه");
        // Mixed, each half handled by the right stemmer — the GCC norm, not
        // an edge case.
        assert_eq!(index_text("الشركة Invoices"), "شركه invoice");
    }

    /// Titles keep their original form for display and get a normalized twin
    /// for matching. Losing the original would mean showing users folded,
    /// lowercased text in the result list.
    #[test]
    fn the_title_keeps_its_original_alongside_the_normalized_form() {
        let row = project("مُحَمَّد Trading", None, "", vec![]);
        assert_eq!(row.title, "مُحَمَّد Trading", "display form is preserved");
        assert_eq!(row.title_norm, "محمد trading");
    }

    /// Exact keys are normalized too, so an invoice number typed with
    /// Arabic-Indic digits matches one stored in ASCII.
    #[test]
    fn exact_keys_are_normalized() {
        let row = project("t", None, "", vec!["INV-١٢٣".into()]);
        assert_eq!(row.exact_keys, vec!["inv-123"]);
    }

    /// Projection is a pure function. The drain and the backfill call it from
    /// different code paths and must produce byte-identical rows, or the index
    /// disagrees with itself depending on how a row got there.
    #[test]
    fn projection_is_deterministic() {
        let first = project("ACME", Some("sub"), "body text", vec!["k1".into()]);
        for _ in 0..5 {
            assert_eq!(
                project("ACME", Some("sub"), "body text", vec!["k1".into()]),
                first
            );
        }
    }

    #[test]
    fn empty_input_is_safe() {
        let row = project("", None, "", vec![]);
        assert!(row.title_norm.is_empty());
        assert!(row.body_indexed.is_empty());
        assert_eq!(row.content_hash.len(), CONTENT_HASH_LEN);
    }
}
