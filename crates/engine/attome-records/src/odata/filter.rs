//! The OData `$filter` grammar Attome reads, parsed into a QuerySpec
//! condition tree. Pure.
//!
//! ```text
//! expr    := and ("or" and)*
//! and     := unary ("and" unary)*
//! unary   := "not" unary | primary
//! primary := "(" expr ")" | func | compare
//! func    := ("contains" | "startswith" | "endswith") "(" path "," literal ")"
//! compare := path op literal | path "in" "(" literal ("," literal)* ")"
//! op      := eq | ne | gt | ge | lt | le
//! path    := name ("/" name)*
//! literal := 'text' (a quote doubled inside) | number | true | false | null
//!          | 2026-10-25 | 2026-10-25T08:30:00Z | a GUID
//! ```
//!
//! `x eq null` and `x ne null` become `is_null` and `is_not_null`. Anything
//! else (arithmetic, lambda operators, other functions, a literal on the left)
//! is refused with a message naming it, never guessed.

use serde_json::{Number, Value};

use crate::query_spec::Condition;

/// The deepest nesting of parentheses and `not` accepted.
const MAX_DEPTH: usize = 32;
/// The most terms in one `in` list.
const MAX_IN: usize = 500;

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Word(String),
    Text(String),
    Open,
    Close,
    Comma,
    Slash,
}

fn tokens(input: &str) -> Result<Vec<Token>, String> {
    let mut out = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                chars.next();
            }
            '(' => {
                chars.next();
                out.push(Token::Open);
            }
            ')' => {
                chars.next();
                out.push(Token::Close);
            }
            ',' => {
                chars.next();
                out.push(Token::Comma);
            }
            '/' => {
                chars.next();
                out.push(Token::Slash);
            }
            '\'' => {
                chars.next();
                let mut text = String::new();
                loop {
                    match chars.next() {
                        None => return Err("a text value is missing its closing quote".into()),
                        Some('\'') if chars.peek() == Some(&'\'') => {
                            chars.next();
                            text.push('\'');
                        }
                        Some('\'') => break,
                        Some(ch) => text.push(ch),
                    }
                }
                out.push(Token::Text(text));
            }
            c if c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | ':' | '+') => {
                let mut word = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch.is_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':' | '+') {
                        word.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }
                out.push(Token::Word(word));
            }
            other => return Err(format!("unexpected character {other:?} in $filter")),
        }
    }
    Ok(out)
}

fn is_name(word: &str) -> bool {
    word.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && word.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn is_guid(word: &str) -> bool {
    let parts: Vec<&str> = word.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(&parts)
            .all(|(n, p)| p.len() == *n && p.chars().all(|c| c.is_ascii_hexdigit()))
}

fn is_date_like(word: &str) -> bool {
    let date = word.get(..10).unwrap_or("");
    chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").is_ok()
        && (word.len() == 10 || chrono::DateTime::parse_from_rfc3339(word).is_ok())
}

/// A literal word (not a quoted text) as a JSON value.
fn literal_word(word: &str) -> Result<Value, String> {
    match word {
        "true" => return Ok(Value::Bool(true)),
        "false" => return Ok(Value::Bool(false)),
        "null" => return Ok(Value::Null),
        _ => {}
    }
    if is_guid(word) || is_date_like(word) {
        return Ok(Value::String(word.to_owned()));
    }
    let trimmed = word
        .strip_suffix(['M', 'm', 'D', 'd', 'L', 'l'])
        .unwrap_or(word);
    if let Ok(n) = trimmed.parse::<i64>() {
        return Ok(Value::Number(n.into()));
    }
    if let Some(n) = trimmed
        .parse::<f64>()
        .ok()
        .filter(|n| n.is_finite())
        .and_then(Number::from_f64)
    {
        return Ok(Value::Number(n));
    }
    Err(format!("{word:?} is not a value $filter understands"))
}

struct Parser {
    tokens: Vec<Token>,
    at: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn bump(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.at).cloned();
        self.at += 1;
        t
    }

    fn keyword(&self, word: &str) -> bool {
        matches!(self.peek(), Some(Token::Word(w)) if w == word)
    }

    fn expect(&mut self, token: &Token, what: &str) -> Result<(), String> {
        match self.bump() {
            Some(t) if &t == token => Ok(()),
            _ => Err(format!("expected {what} in $filter")),
        }
    }

    fn or(&mut self, depth: usize) -> Result<Condition, String> {
        let mut any = vec![self.and(depth)?];
        while self.keyword("or") {
            self.at += 1;
            any.push(self.and(depth)?);
        }
        Ok(if any.len() == 1 {
            any.remove(0)
        } else {
            Condition::Or { any }
        })
    }

    fn and(&mut self, depth: usize) -> Result<Condition, String> {
        let mut all = vec![self.unary(depth)?];
        while self.keyword("and") {
            self.at += 1;
            all.push(self.unary(depth)?);
        }
        Ok(if all.len() == 1 {
            all.remove(0)
        } else {
            Condition::And { all }
        })
    }

    fn unary(&mut self, depth: usize) -> Result<Condition, String> {
        if depth > MAX_DEPTH {
            return Err("$filter is nested too deeply".into());
        }
        if self.keyword("not") {
            self.at += 1;
            return Ok(Condition::Not {
                condition: Box::new(self.unary(depth + 1)?),
            });
        }
        if self.peek() == Some(&Token::Open) {
            self.at += 1;
            let inner = self.or(depth + 1)?;
            self.expect(&Token::Close, "a closing parenthesis")?;
            return Ok(inner);
        }
        self.primary()
    }

    fn path(&mut self) -> Result<String, String> {
        let mut parts = Vec::new();
        loop {
            match self.bump() {
                Some(Token::Word(w)) if is_name(&w) => parts.push(w),
                Some(Token::Text(_)) => {
                    return Err("$filter compares a field with a value, field first".into());
                }
                _ => return Err("expected a field name in $filter".into()),
            }
            if self.peek() == Some(&Token::Slash) {
                self.at += 1;
            } else {
                break;
            }
        }
        if parts.len() > 4 {
            return Err("a $filter path reaches at most three lookups".into());
        }
        Ok(parts.join("."))
    }

    fn literal(&mut self) -> Result<Value, String> {
        match self.bump() {
            Some(Token::Text(t)) => Ok(Value::String(t)),
            Some(Token::Word(w)) => literal_word(&w),
            _ => Err("expected a value in $filter".into()),
        }
    }

    fn primary(&mut self) -> Result<Condition, String> {
        if let Some(Token::Word(w)) = self.peek().cloned()
            && self.tokens.get(self.at + 1) == Some(&Token::Open)
        {
            let op = match w.as_str() {
                "contains" => "contains",
                "startswith" => "starts_with",
                "endswith" => "ends_with",
                other => return Err(format!("the $filter function {other}() is not supported")),
            };
            self.at += 2;
            let field = self.path()?;
            self.expect(&Token::Comma, "a comma")?;
            let value = self.literal()?;
            self.expect(&Token::Close, "a closing parenthesis")?;
            if !value.is_string() {
                return Err(format!("{w}() takes a text value"));
            }
            return Ok(Condition::Compare {
                field,
                op: op.into(),
                value: Some(value),
            });
        }
        let field = self.path()?;
        let op = match self.bump() {
            Some(Token::Word(w)) => w,
            _ => return Err("expected an operator after a field in $filter".into()),
        };
        if op == "in" {
            self.expect(&Token::Open, "a parenthesis after in")?;
            let mut values = vec![self.literal()?];
            while self.peek() == Some(&Token::Comma) {
                self.at += 1;
                values.push(self.literal()?);
                if values.len() > MAX_IN {
                    return Err(format!("an in list has at most {MAX_IN} values"));
                }
            }
            self.expect(&Token::Close, "a closing parenthesis")?;
            return Ok(Condition::Compare {
                field,
                op: "in".into(),
                value: Some(Value::Array(values)),
            });
        }
        let mapped = match op.as_str() {
            "eq" => "eq",
            "ne" => "neq",
            "gt" => "gt",
            "ge" => "gte",
            "lt" => "lt",
            "le" => "lte",
            "has" | "add" | "sub" | "mul" | "div" | "mod" => {
                return Err(format!("the $filter operator {op} is not supported"));
            }
            other => return Err(format!("{other:?} is not a $filter operator")),
        };
        let value = self.literal()?;
        Ok(match (mapped, value) {
            ("eq", Value::Null) => Condition::Compare {
                field,
                op: "is_null".into(),
                value: None,
            },
            ("neq", Value::Null) => Condition::Compare {
                field,
                op: "is_not_null".into(),
                value: None,
            },
            (_, Value::Null) => {
                return Err("null is compared only with eq or ne".into());
            }
            (op, value) => Condition::Compare {
                field,
                op: op.into(),
                value: Some(value),
            },
        })
    }
}

/// Parses a `$filter` expression.
pub fn parse(input: &str) -> Result<Condition, String> {
    if input.len() > 8_000 {
        return Err("$filter is longer than 8,000 characters".into());
    }
    let tokens = tokens(input)?;
    if tokens.is_empty() {
        return Err("$filter is empty".into());
    }
    let mut parser = Parser { tokens, at: 0 };
    let condition = parser.or(0)?;
    if parser.at < parser.tokens.len() {
        return Err("$filter has words left over after a complete expression".into());
    }
    Ok(condition)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn cmp(field: &str, op: &str, value: Value) -> Condition {
        Condition::Compare {
            field: field.into(),
            op: op.into(),
            value: Some(value),
        }
    }

    #[test]
    fn odata_filter_comparisons_and_logic() {
        assert_eq!(
            parse("name eq 'O''Brien'").unwrap(),
            cmp("name", "eq", json!("O'Brien"))
        );
        assert_eq!(
            parse("amount ge 100.5 and (city eq 'Riyadh' or city eq 'Jeddah')").unwrap(),
            Condition::And {
                all: vec![
                    cmp("amount", "gte", json!(100.5)),
                    Condition::Or {
                        any: vec![
                            cmp("city", "eq", json!("Riyadh")),
                            cmp("city", "eq", json!("Jeddah"))
                        ]
                    }
                ]
            }
        );
        assert_eq!(
            parse("not is_active eq true").unwrap(),
            Condition::Not {
                condition: Box::new(cmp("is_active", "eq", json!(true)))
            }
        );
        assert_eq!(parse("count lt 5").unwrap(), cmp("count", "lt", json!(5)));
        assert_eq!(
            parse("total le 2.5M").unwrap(),
            cmp("total", "lte", json!(2.5))
        );
    }

    #[test]
    fn odata_filter_functions_paths_and_lists() {
        assert_eq!(
            parse("contains(name,'شركة')").unwrap(),
            cmp("name", "contains", json!("شركة"))
        );
        assert_eq!(
            parse("startswith(primary_contact/team/name, 'Sales')").unwrap(),
            cmp("primary_contact.team.name", "starts_with", json!("Sales"))
        );
        assert_eq!(
            parse("status in ('open', 'won')").unwrap(),
            cmp("status", "in", json!(["open", "won"]))
        );
    }

    #[test]
    fn odata_filter_null_dates_and_guids() {
        assert_eq!(
            parse("closed_at eq null").unwrap(),
            Condition::Compare {
                field: "closed_at".into(),
                op: "is_null".into(),
                value: None
            }
        );
        assert_eq!(
            parse("owner ne null").unwrap(),
            Condition::Compare {
                field: "owner".into(),
                op: "is_not_null".into(),
                value: None
            }
        );
        assert_eq!(
            parse("created_at gt 2026-10-01T00:00:00Z").unwrap(),
            cmp("created_at", "gt", json!("2026-10-01T00:00:00Z"))
        );
        assert_eq!(
            parse("due eq 2026-10-25").unwrap(),
            cmp("due", "eq", json!("2026-10-25"))
        );
        assert_eq!(
            parse("account eq 0190f2a1-7b3c-7d4e-8f00-123456789abc").unwrap(),
            cmp(
                "account",
                "eq",
                json!("0190f2a1-7b3c-7d4e-8f00-123456789abc")
            )
        );
    }

    #[test]
    fn odata_filter_refuses_what_it_does_not_read() {
        for bad in [
            "",
            "name eq",
            "'x' eq name",
            "amount add 1 eq 2",
            "tags/any(t: t eq 'a')",
            "length(name) gt 3",
            "name eq 'open",
            "amount gt null",
            "(name eq 'a'",
            "name eq 'a' name",
            "a/b/c/d/e eq 1",
            "name eq 'a' ; drop",
        ] {
            assert!(parse(bad).is_err(), "{bad:?} should be refused");
        }
        let deep = format!("{}a eq 1{}", "(".repeat(40), ")".repeat(40));
        assert!(parse(&deep).is_err());
    }
}
