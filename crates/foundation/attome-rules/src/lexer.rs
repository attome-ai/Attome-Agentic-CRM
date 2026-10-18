//! Hand-written lexer (no external parsing crate — see the crate-level docs
//! in `lib.rs` and `document/decisions/foundation/D-399.md` for why). Byte
//! positions are tracked so `RulesError::Parse` can point at the offending
//! character, and every token carries its start **and end** byte offset so the
//! parser can build BRU-FX1's span table.
//!
//! Walks `char_indices()`, never raw bytes: the platform is bilingual
//! (Arabic + English, per `document/decisions`'s recurring framing), so a
//! string literal like `"مرحبا"` is an ordinary, expected input. Indexing
//! `src.as_bytes()` and casting a lone byte to `char` — the naive approach —
//! both corrupts multi-byte UTF-8 content and can panic by slicing on a
//! non-char-boundary offset; neither is acceptable here (coding-guidelines
//! §6, no panics).
//!
//! Since BRU-B1 an overflowing numeric literal (`1e999`) is rejected here as
//! `RulesError::NumericOverflow`, so no non-finite `f64` can enter the AST.

use crate::budget::HARD_MAX_SOURCE_BYTES;
use crate::error::{BudgetKind, RulesError};

// C-25 pub(crate) sweep: `mod lexer` is private (see `lib.rs`) and none of
// TokKind/Token/lex is re-exported at the crate root — `pub` here was dead
// visibility, reachable only from `parser.rs` within this crate either way.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TokKind {
    Number(f64),
    Str(String),
    Ident(String),
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Dot,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    EqEq,
    NotEq,
    Lt,
    Le,
    Gt,
    Ge,
    /// Z11-T3: `=>`, a lambda's arrow.
    Arrow,
    Eof,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Token {
    pub(crate) kind: TokKind,
    /// Byte offset of the token's first character.
    pub(crate) pos: usize,
    /// Byte offset just past the token's last character (BRU-FX1).
    pub(crate) end: usize,
}

/// Char-index cursor over the source, giving lookahead by *character*
/// (`peek`/`peek2`) while still reporting byte offsets (`pos`) for errors —
/// `RulesError::Parse { pos, .. }` is a byte offset into the original `&str`,
/// which is what a caller would use to highlight the source.
struct Cursor<'a> {
    src: &'a str,
    chars: Vec<(usize, char)>,
    idx: usize,
}

impl<'a> Cursor<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            src,
            chars: src.char_indices().collect(),
            idx: 0,
        }
    }

    fn pos(&self) -> usize {
        self.chars
            .get(self.idx)
            .map(|(b, _)| *b)
            .unwrap_or(self.src.len())
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.idx).map(|(_, c)| *c)
    }

    fn peek2(&self) -> Option<char> {
        self.chars.get(self.idx + 1).map(|(_, c)| *c)
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.idx += 1;
        }
        c
    }
}

pub(crate) fn lex(src: &str) -> Result<Vec<Token>, RulesError> {
    if src.len() > HARD_MAX_SOURCE_BYTES {
        return Err(RulesError::Budget(BudgetKind::SourceLength));
    }

    let mut cur = Cursor::new(src);
    let mut tokens = Vec::new();

    while let Some(c) = cur.peek() {
        if c.is_whitespace() {
            cur.bump();
            continue;
        }

        let start = cur.pos();
        let kind = match c {
            '(' => {
                cur.bump();
                TokKind::LParen
            }
            ')' => {
                cur.bump();
                TokKind::RParen
            }
            '[' => {
                cur.bump();
                TokKind::LBracket
            }
            ']' => {
                cur.bump();
                TokKind::RBracket
            }
            ',' => {
                cur.bump();
                TokKind::Comma
            }
            '.' => {
                cur.bump();
                TokKind::Dot
            }
            '+' => {
                cur.bump();
                TokKind::Plus
            }
            '-' => {
                cur.bump();
                TokKind::Minus
            }
            '*' => {
                cur.bump();
                TokKind::Star
            }
            '/' => {
                cur.bump();
                TokKind::Slash
            }
            '%' => {
                cur.bump();
                TokKind::Percent
            }
            '=' => {
                cur.bump();
                if cur.peek() == Some('=') {
                    cur.bump();
                    TokKind::EqEq
                } else if cur.peek() == Some('>') {
                    cur.bump();
                    TokKind::Arrow
                } else {
                    return Err(RulesError::Parse {
                        message: "unexpected '=' (did you mean '=='?)".to_owned(),
                        pos: start,
                    });
                }
            }
            '!' => {
                cur.bump();
                if cur.peek() == Some('=') {
                    cur.bump();
                    TokKind::NotEq
                } else {
                    return Err(RulesError::Parse {
                        message: "unexpected '!' (did you mean '!='?)".to_owned(),
                        pos: start,
                    });
                }
            }
            '<' => {
                cur.bump();
                if cur.peek() == Some('=') {
                    cur.bump();
                    TokKind::Le
                } else {
                    TokKind::Lt
                }
            }
            '>' => {
                cur.bump();
                if cur.peek() == Some('=') {
                    cur.bump();
                    TokKind::Ge
                } else {
                    TokKind::Gt
                }
            }
            '"' => TokKind::Str(lex_string(&mut cur, start)?),
            c if c.is_ascii_digit() => TokKind::Number(lex_number(&mut cur)?),
            c if c.is_alphabetic() || c == '_' => TokKind::Ident(lex_ident(&mut cur)),
            other => {
                return Err(RulesError::Parse {
                    message: format!("unexpected character '{other}'"),
                    pos: start,
                });
            }
        };
        let end = cur.pos();
        tokens.push(Token {
            kind,
            pos: start,
            end,
        });
    }

    tokens.push(Token {
        kind: TokKind::Eof,
        pos: src.len(),
        end: src.len(),
    });
    Ok(tokens)
}

fn lex_number(cur: &mut Cursor<'_>) -> Result<f64, RulesError> {
    let start = cur.pos();
    while matches!(cur.peek(), Some(c) if c.is_ascii_digit()) {
        cur.bump();
    }
    if cur.peek() == Some('.') && matches!(cur.peek2(), Some(c) if c.is_ascii_digit()) {
        cur.bump();
        while matches!(cur.peek(), Some(c) if c.is_ascii_digit()) {
            cur.bump();
        }
    }
    if matches!(cur.peek(), Some('e') | Some('E')) {
        let save = cur.idx;
        cur.bump();
        if matches!(cur.peek(), Some('+') | Some('-')) {
            cur.bump();
        }
        if matches!(cur.peek(), Some(c) if c.is_ascii_digit()) {
            while matches!(cur.peek(), Some(c) if c.is_ascii_digit()) {
                cur.bump();
            }
        } else {
            cur.idx = save; // not actually an exponent — back out
        }
    }
    let end = cur.pos();
    let text = &cur.src[start..end];
    // BRU-B1: `"1e999".parse::<f64>()` is `Ok(inf)`, so a finite-only
    // `Value::Number` invariant (D-399 ruling 4 / `value.rs`) requires
    // rejecting the literal here. The message deliberately carries no value.
    match text.parse::<f64>() {
        Ok(n) if n.is_finite() => Ok(n),
        Ok(_) => Err(RulesError::NumericOverflow),
        // `text` is a validated numeric lexeme built above from ASCII digits
        // only, so this cannot fail for a well-formed input; return a typed
        // error rather than panicking (coding-guidelines §6).
        Err(_) => Err(RulesError::Parse {
            message: "malformed number literal".to_owned(),
            pos: start,
        }),
    }
}

fn lex_ident(cur: &mut Cursor<'_>) -> String {
    let start = cur.pos();
    while matches!(cur.peek(), Some(c) if c.is_alphanumeric() || c == '_') {
        cur.bump();
    }
    let end = cur.pos();
    cur.src[start..end].to_owned()
}

fn lex_string(cur: &mut Cursor<'_>, start: usize) -> Result<String, RulesError> {
    cur.bump(); // opening quote
    let mut out = String::new();
    loop {
        match cur.peek() {
            None => {
                return Err(RulesError::Parse {
                    message: "unterminated string literal".to_owned(),
                    pos: start,
                });
            }
            Some('"') => {
                cur.bump();
                break;
            }
            Some('\\') => {
                let esc_pos = cur.pos();
                cur.bump();
                match cur.bump() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some(other) => {
                        return Err(RulesError::Parse {
                            message: format!("unknown escape '\\{other}'"),
                            pos: esc_pos,
                        });
                    }
                    None => {
                        return Err(RulesError::Parse {
                            message: "unterminated string literal".to_owned(),
                            pos: start,
                        });
                    }
                }
            }
            Some(c) => {
                out.push(c);
                cur.bump();
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexes_operators_and_literals() {
        let toks = lex(r#"a.b + 1 == "x" and not false <= 2.5e1"#).expect("lex");
        let kinds: Vec<_> = toks.into_iter().map(|t| t.kind).collect();
        assert_eq!(
            kinds,
            vec![
                TokKind::Ident("a".into()),
                TokKind::Dot,
                TokKind::Ident("b".into()),
                TokKind::Plus,
                TokKind::Number(1.0),
                TokKind::EqEq,
                TokKind::Str("x".into()),
                TokKind::Ident("and".into()),
                TokKind::Ident("not".into()),
                TokKind::Ident("false".into()),
                TokKind::Le,
                TokKind::Number(25.0),
                TokKind::Eof,
            ]
        );
    }

    #[test]
    fn token_spans_are_byte_exact() {
        let toks = lex("amount  +  name").expect("lex");
        assert_eq!(toks[0].pos, 0);
        assert_eq!(toks[0].end, 6);
        assert_eq!(toks[1].pos, 8);
        assert_eq!(toks[1].end, 9);
        assert_eq!(toks[2].pos, 11);
        assert_eq!(toks[2].end, 15);
    }

    #[test]
    fn rejects_oversized_source() {
        let huge = "1".repeat(HARD_MAX_SOURCE_BYTES + 1);
        assert_eq!(
            lex(&huge),
            Err(RulesError::Budget(BudgetKind::SourceLength))
        );
    }

    #[test]
    fn overflowing_literal_is_rejected_not_infinite() {
        // BRU-B1: `1e999` parses as `inf` in Rust; the lexer must reject it.
        assert_eq!(lex("1e999"), Err(RulesError::NumericOverflow));
        assert_eq!(
            lex("1e308"),
            Ok(vec![
                Token {
                    kind: TokKind::Number(1e308),
                    pos: 0,
                    end: 5,
                },
                Token {
                    kind: TokKind::Eof,
                    pos: 5,
                    end: 5,
                },
            ])
        );
    }

    #[test]
    fn unterminated_string_is_a_parse_error_not_a_panic() {
        assert!(lex(r#""abc"#).is_err());
    }

    #[test]
    fn string_escapes() {
        let toks = lex(r#""a\"b\\c\n""#).expect("lex");
        assert_eq!(toks[0].kind, TokKind::Str("a\"b\\c\n".to_owned()));
    }

    #[test]
    fn multibyte_string_literal_round_trips() {
        // Arabic text inside a string literal — the platform is bilingual;
        // this must not corrupt the content or panic on a byte-boundary slice.
        let toks = lex(r#"contains(field, "مرحبا")"#).expect("lex");
        // Ident(contains) LParen Ident(field) Comma Str(...) RParen Eof
        assert_eq!(toks[4].kind, TokKind::Str("مرحبا".to_owned()));
        assert_eq!(
            &"contains(field, \"مرحبا\")"[toks[4].pos..toks[4].end],
            "\"مرحبا\""
        );
    }

    #[test]
    fn unexpected_multibyte_character_is_a_parse_error_not_a_panic() {
        // An emoji is alphabetic()==false, digit==false, so it falls into
        // the `other` arm — must format!() and return cleanly, not panic
        // on a byte-boundary slice.
        assert!(lex("1 + 🎉").is_err());
    }
}
