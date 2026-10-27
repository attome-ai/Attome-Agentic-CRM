//! The SQL-like text form of a QuerySpec (roadmap S4-T8). A hand-written
//! tokenizer and recursive-descent parser turn the text into the same
//! [`QuerySpec`] the JSON form gives; the text itself never reaches the
//! database, only the parsed spec goes on to `compile`.
//!
//! ```text
//! SELECT <field | agg(field) AS alias>, ... FROM <entity>
//!   [WHERE <cond>] [GROUP BY <field | bucket(field, month)>, ...]
//!   [HAVING <cond>] [ORDER BY <field> [ASC | DESC], ...] [LIMIT n]
//! ```
//!
//! A condition is `field op value`, `field IN (v, ...)`, `field NOT IN (...)`,
//! `field BETWEEN a AND b`, `field IS [NOT] NULL`, `EXISTS(path [WHERE cond])`,
//! `NOT EXISTS(...)`, `field op :param`, or a word operator (`contains 'x'`,
//! `last_n_days(30)`, `mine`), joined with AND, OR, NOT and parentheses.
//! Keywords are case-insensitive; names are lower case.

use attome_types::AppError;
use serde_json::Value;

use super::model::{
    AggFunc, Aggregate, Condition, DateBucket, GroupKey, OPERATORS, QuerySpec, SortKey,
};

/// The longest text accepted.
pub const MAX_TEXT_BYTES: usize = 8 * 1024;
/// The most tokens a WHERE clause may hold.
pub const MAX_WHERE_TOKENS: usize = 200;

const KEYWORDS: &[&str] = &[
    "SELECT", "FROM", "WHERE", "GROUP", "BY", "HAVING", "ORDER", "ASC", "DESC", "LIMIT", "AND",
    "OR", "NOT", "IN", "BETWEEN", "IS", "NULL", "EXISTS", "AS", "TRUE", "FALSE",
];

/// Word operators that take no value.
const UNARY_OPS: &[&str] = &[
    "today",
    "this_month",
    "last_month",
    "this_quarter",
    "this_year",
    "mine",
    "my_team",
];

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    /// An upper-cased keyword.
    Kw(&'static str),
    Ident(String),
    Str(String),
    Num(String),
    Param(String),
    Sym(&'static str),
}

#[derive(Debug, Clone)]
struct Token {
    tok: Tok,
    /// Character position in the text, from 1.
    pos: usize,
}

fn error(pos: usize, what: &str) -> AppError {
    AppError::Validation(format!("query text: {what} at position {pos}"))
}

fn tokenize(text: &str) -> Result<Vec<Token>, AppError> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let pos = i + 1;
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len()
                && (chars[i].is_ascii_alphanumeric() || chars[i] == '_' || chars[i] == '.')
            {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            let upper = word.to_ascii_uppercase();
            let tok = match KEYWORDS.iter().find(|k| **k == upper) {
                Some(kw) => Tok::Kw(kw),
                None if is_name(&word) => Tok::Ident(word),
                None => return Err(error(pos, &format!("invalid name '{word}'"))),
            };
            out.push(Token { tok, pos });
            continue;
        }
        if c.is_ascii_digit() || (c == '-' && chars.get(i + 1).is_some_and(char::is_ascii_digit)) {
            let start = i;
            i += 1;
            while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                i += 1;
            }
            let num: String = chars[start..i].iter().collect();
            if serde_json::from_str::<serde_json::Number>(&num).is_err() {
                return Err(error(pos, &format!("invalid number '{num}'")));
            }
            out.push(Token {
                tok: Tok::Num(num),
                pos,
            });
            continue;
        }
        if c == '\'' {
            let mut value = String::new();
            i += 1;
            loop {
                match chars.get(i) {
                    None => return Err(error(pos, "unterminated string")),
                    Some('\'') if chars.get(i + 1) == Some(&'\'') => {
                        value.push('\'');
                        i += 2;
                    }
                    Some('\'') => {
                        i += 1;
                        break;
                    }
                    Some(ch) => {
                        value.push(*ch);
                        i += 1;
                    }
                }
            }
            out.push(Token {
                tok: Tok::Str(value),
                pos,
            });
            continue;
        }
        if c == ':' {
            let start = i + 1;
            i += 1;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let name: String = chars[start..i].iter().collect();
            if !is_name(&name) || name.contains('.') {
                return Err(error(pos, "invalid parameter name"));
            }
            out.push(Token {
                tok: Tok::Param(name),
                pos,
            });
            continue;
        }
        let two: String = chars[i..chars.len().min(i + 2)].iter().collect();
        let sym = match two.as_str() {
            "!=" | "<>" => Some(("!=", 2)),
            ">=" => Some((">=", 2)),
            "<=" => Some(("<=", 2)),
            _ => match c {
                '=' => Some(("=", 1)),
                '>' => Some((">", 1)),
                '<' => Some(("<", 1)),
                '(' => Some(("(", 1)),
                ')' => Some((")", 1)),
                ',' => Some((",", 1)),
                '*' => Some(("*", 1)),
                _ => None,
            },
        };
        match sym {
            Some((s, len)) => {
                out.push(Token {
                    tok: Tok::Sym(s),
                    pos,
                });
                i += len;
            }
            None => return Err(error(pos, &format!("unexpected character '{c}'"))),
        }
    }
    Ok(out)
}

/// `[a-z_][a-z0-9_.]*`
fn is_name(word: &str) -> bool {
    let mut chars = word.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.')
        && !word.ends_with('.')
        && !word.contains("..")
}

struct Parser {
    toks: Vec<Token>,
    at: usize,
    end_pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.at).map(|t| &t.tok)
    }

    fn peek_at(&self, n: usize) -> Option<&Tok> {
        self.toks.get(self.at + n).map(|t| &t.tok)
    }

    fn pos(&self) -> usize {
        self.toks.get(self.at).map_or(self.end_pos, |t| t.pos)
    }

    fn fail<T>(&self, what: &str) -> Result<T, AppError> {
        Err(error(self.pos(), what))
    }

    fn eat_kw(&mut self, kw: &str) -> bool {
        if matches!(self.peek(), Some(Tok::Kw(k)) if *k == kw) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn expect_kw(&mut self, kw: &str) -> Result<(), AppError> {
        if self.eat_kw(kw) {
            Ok(())
        } else {
            self.fail(&format!("expected {kw}"))
        }
    }

    fn eat_sym(&mut self, sym: &str) -> bool {
        if matches!(self.peek(), Some(Tok::Sym(s)) if *s == sym) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn expect_sym(&mut self, sym: &str) -> Result<(), AppError> {
        if self.eat_sym(sym) {
            Ok(())
        } else {
            self.fail(&format!("expected '{sym}'"))
        }
    }

    fn ident(&mut self) -> Result<String, AppError> {
        match self.peek() {
            Some(Tok::Ident(name)) => {
                let name = name.clone();
                self.at += 1;
                Ok(name)
            }
            _ => self.fail("expected a name"),
        }
    }

    fn query(&mut self) -> Result<QuerySpec, AppError> {
        self.expect_kw("SELECT")?;
        let mut select = Vec::new();
        let mut aggregates = Vec::new();
        loop {
            match agg_func(self.peek(), self.peek_at(1)) {
                Some(func) => {
                    self.at += 2;
                    let field = if self.eat_sym("*") {
                        if func != AggFunc::Count {
                            return self.fail("only count takes *");
                        }
                        None
                    } else {
                        Some(self.ident()?)
                    };
                    self.expect_sym(")")?;
                    self.expect_kw("AS")?;
                    let alias = self.ident()?;
                    aggregates.push(Aggregate { func, field, alias });
                }
                None => select.push(self.ident()?),
            }
            if !self.eat_sym(",") {
                break;
            }
        }
        self.expect_kw("FROM")?;
        let entity = self.ident()?;
        if entity.contains('.') {
            return self.fail("expected an entity name");
        }

        let r#where = if self.eat_kw("WHERE") {
            let start = self.at;
            let cond = self.condition()?;
            if self.at - start > MAX_WHERE_TOKENS {
                return Err(error(
                    self.toks[start].pos,
                    &format!("WHERE holds more than {MAX_WHERE_TOKENS} tokens"),
                ));
            }
            Some(cond)
        } else {
            None
        };

        let mut group_by = Vec::new();
        if self.eat_kw("GROUP") {
            self.expect_kw("BY")?;
            loop {
                let is_bucket = matches!(self.peek(), Some(Tok::Ident(n)) if n == "bucket")
                    && self.peek_at(1) == Some(&Tok::Sym("("));
                if is_bucket {
                    self.at += 2;
                    let field = self.ident()?;
                    self.expect_sym(",")?;
                    let bucket = match self.ident()?.as_str() {
                        "day" => DateBucket::Day,
                        "week" => DateBucket::Week,
                        "month" => DateBucket::Month,
                        "quarter" => DateBucket::Quarter,
                        "year" => DateBucket::Year,
                        _ => return self.fail("expected day, week, month, quarter or year"),
                    };
                    self.expect_sym(")")?;
                    group_by.push(GroupKey {
                        field,
                        bucket: Some(bucket),
                    });
                } else {
                    group_by.push(GroupKey {
                        field: self.ident()?,
                        bucket: None,
                    });
                }
                if !self.eat_sym(",") {
                    break;
                }
            }
        }

        let having = if self.eat_kw("HAVING") {
            Some(self.condition()?)
        } else {
            None
        };

        let mut sort = Vec::new();
        if self.eat_kw("ORDER") {
            self.expect_kw("BY")?;
            loop {
                let field = self.ident()?;
                let desc = if self.eat_kw("DESC") {
                    true
                } else {
                    self.eat_kw("ASC");
                    false
                };
                sort.push(SortKey { field, desc });
                if !self.eat_sym(",") {
                    break;
                }
            }
        }

        let page_size = if self.eat_kw("LIMIT") {
            match self.peek().and_then(|t| match t {
                Tok::Num(n) => n.parse::<i64>().ok(),
                _ => None,
            }) {
                Some(n) => {
                    self.at += 1;
                    Some(n)
                }
                None => return self.fail("LIMIT takes a whole number"),
            }
        } else {
            None
        };

        if self.at < self.toks.len() {
            return self.fail("unexpected text");
        }
        Ok(QuerySpec {
            entity,
            select,
            r#where,
            sort,
            page_size,
            cursor: None,
            group_by,
            aggregates,
            having,
            explain: false,
            as_of: None,
            params: Default::default(),
            totals: None,
        })
    }

    /// `or := and (OR and)*`
    fn condition(&mut self) -> Result<Condition, AppError> {
        let mut any = vec![self.and()?];
        while self.eat_kw("OR") {
            any.push(self.and()?);
        }
        Ok(if any.len() == 1 {
            any.remove(0)
        } else {
            Condition::Or { any }
        })
    }

    /// `and := not (AND not)*`
    fn and(&mut self) -> Result<Condition, AppError> {
        let mut all = vec![self.not()?];
        while self.eat_kw("AND") {
            all.push(self.not()?);
        }
        Ok(if all.len() == 1 {
            all.remove(0)
        } else {
            Condition::And { all }
        })
    }

    /// `not := NOT not | NOT EXISTS(...) | primary`
    fn not(&mut self) -> Result<Condition, AppError> {
        if self.eat_kw("NOT") {
            if self.eat_kw("EXISTS") {
                let (path, r#where) = self.exists_body()?;
                return Ok(Condition::NotExists { path, r#where });
            }
            return Ok(Condition::Not {
                condition: Box::new(self.not()?),
            });
        }
        self.primary()
    }

    fn exists_body(&mut self) -> Result<(String, Option<Box<Condition>>), AppError> {
        self.expect_sym("(")?;
        let path = self.ident()?;
        let r#where = if self.eat_kw("WHERE") {
            Some(Box::new(self.condition()?))
        } else {
            None
        };
        self.expect_sym(")")?;
        Ok((path, r#where))
    }

    fn primary(&mut self) -> Result<Condition, AppError> {
        if self.eat_sym("(") {
            let cond = self.condition()?;
            self.expect_sym(")")?;
            return Ok(cond);
        }
        if self.eat_kw("EXISTS") {
            let (path, r#where) = self.exists_body()?;
            return Ok(Condition::Exists { path, r#where });
        }
        let field = self.ident()?;
        let compare = |op: &str, value: Option<Value>| Condition::Compare {
            field: field.clone(),
            op: op.to_owned(),
            value,
        };

        if self.eat_kw("IS") {
            let negated = self.eat_kw("NOT");
            self.expect_kw("NULL")?;
            return Ok(compare(
                if negated { "is_not_null" } else { "is_null" },
                None,
            ));
        }
        if self.eat_kw("NOT") {
            self.expect_kw("IN")?;
            return Ok(compare("not_in", Some(self.list()?)));
        }
        if self.eat_kw("IN") {
            return Ok(compare("in", Some(self.list()?)));
        }
        if self.eat_kw("BETWEEN") {
            let low = self.value()?;
            self.expect_kw("AND")?;
            let high = self.value()?;
            return Ok(compare("between", Some(Value::Array(vec![low, high]))));
        }

        let op = match self.peek() {
            Some(Tok::Sym(s)) => {
                let op = match *s {
                    "=" => "eq",
                    "!=" => "neq",
                    ">" => "gt",
                    ">=" => "gte",
                    "<" => "lt",
                    "<=" => "lte",
                    _ => return self.fail("expected an operator"),
                };
                self.at += 1;
                op.to_owned()
            }
            Some(Tok::Ident(word)) if is_word_op(word) => {
                let op = word.clone();
                self.at += 1;
                op
            }
            _ => return self.fail("expected an operator"),
        };

        if UNARY_OPS.contains(&op.as_str()) {
            return Ok(compare(&op, None));
        }
        if let Some(Tok::Param(name)) = self.peek() {
            let param = name.clone();
            self.at += 1;
            return Ok(Condition::Param { field, op, param });
        }
        // `last_n_days(30)`, `contains_any('a', 'b')`: a parenthesised value.
        if self.peek() == Some(&Tok::Sym("(")) {
            let list = self.list()?;
            let value = match list {
                Value::Array(mut items) if items.len() == 1 && op.ends_with("_days") => {
                    items.remove(0)
                }
                other => other,
            };
            return Ok(compare(&op, Some(value)));
        }
        Ok(compare(&op, Some(self.value()?)))
    }

    /// `( value, ... )`
    fn list(&mut self) -> Result<Value, AppError> {
        self.expect_sym("(")?;
        let mut items = vec![self.value()?];
        while self.eat_sym(",") {
            items.push(self.value()?);
        }
        self.expect_sym(")")?;
        Ok(Value::Array(items))
    }

    fn value(&mut self) -> Result<Value, AppError> {
        match self.peek().cloned() {
            Some(Tok::Str(s)) => {
                self.at += 1;
                Ok(Value::String(s))
            }
            Some(Tok::Num(n)) => {
                self.at += 1;
                serde_json::from_str::<serde_json::Number>(&n)
                    .map(Value::Number)
                    .or_else(|_| self.fail("invalid number"))
            }
            Some(Tok::Kw("TRUE")) => {
                self.at += 1;
                Ok(Value::Bool(true))
            }
            Some(Tok::Kw("FALSE")) => {
                self.at += 1;
                Ok(Value::Bool(false))
            }
            _ => self.fail("expected a value"),
        }
    }
}

/// A word operator: every [`OPERATORS`] entry that has no symbol or keyword
/// form of its own.
fn is_word_op(word: &str) -> bool {
    OPERATORS.contains(&word)
        && !matches!(
            word,
            "eq" | "neq"
                | "gt"
                | "gte"
                | "lt"
                | "lte"
                | "in"
                | "not_in"
                | "between"
                | "is_null"
                | "is_not_null"
        )
}

fn agg_func(tok: Option<&Tok>, next: Option<&Tok>) -> Option<AggFunc> {
    let Some(Tok::Ident(name)) = tok else {
        return None;
    };
    if next != Some(&Tok::Sym("(")) {
        return None;
    }
    Some(match name.as_str() {
        "count" => AggFunc::Count,
        "sum" => AggFunc::Sum,
        "avg" => AggFunc::Avg,
        "min" => AggFunc::Min,
        "max" => AggFunc::Max,
        "count_distinct" => AggFunc::CountDistinct,
        _ => return None,
    })
}

/// Parses the text form into a [`QuerySpec`]. Anything outside the grammar is
/// a 422 naming its position.
pub fn parse(text: &str) -> Result<QuerySpec, AppError> {
    if text.len() > MAX_TEXT_BYTES {
        return Err(AppError::Validation(format!(
            "query text is longer than {MAX_TEXT_BYTES} bytes"
        )));
    }
    let toks = tokenize(text)?;
    let mut parser = Parser {
        toks,
        at: 0,
        end_pos: text.chars().count() + 1,
    };
    parser.query()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn spec(doc: Value) -> QuerySpec {
        serde_json::from_value(doc).expect("spec")
    }

    #[test]
    fn parses_select_where_order_limit() {
        let parsed = parse(
            "select name, revenue FROM account WHERE revenue >= 1000 AND name != 'x' \
             ORDER BY revenue DESC, name LIMIT 25",
        )
        .unwrap();
        assert_eq!(
            parsed,
            spec(json!({
                "entity": "account",
                "select": ["name", "revenue"],
                "where": {"kind": "and", "all": [
                    {"kind": "compare", "field": "revenue", "op": "gte", "value": 1000},
                    {"kind": "compare", "field": "name", "op": "neq", "value": "x"}
                ]},
                "sort": [{"field": "revenue", "desc": true}, {"field": "name", "desc": false}],
                "page_size": 25
            }))
        );
    }

    #[test]
    fn parses_exists_and_group_by_bucket() {
        let parsed = parse(
            "SELECT count(*) AS n, sum(amount) AS total FROM opportunity \
             WHERE NOT EXISTS(account.incidents WHERE statecode = 0) \
             GROUP BY owner_ref, bucket(closedate, quarter) HAVING total > 100",
        )
        .unwrap();
        assert_eq!(
            parsed,
            spec(json!({
                "entity": "opportunity",
                "aggregates": [
                    {"func": "count", "alias": "n"},
                    {"func": "sum", "field": "amount", "alias": "total"}
                ],
                "where": {"kind": "not_exists", "path": "account.incidents",
                          "where": {"kind": "compare", "field": "statecode", "op": "eq", "value": 0}},
                "group_by": [{"field": "owner_ref"}, {"field": "closedate", "bucket": "quarter"}],
                "having": {"kind": "compare", "field": "total", "op": "gt", "value": 100}
            }))
        );
    }

    #[test]
    fn rejects_semicolon_and_comments() {
        for (text, pos) in [
            ("SELECT name FROM account; DROP TABLE account", 25),
            ("SELECT name FROM account -- all", 26),
            ("SELECT name /* x */ FROM account", 13),
            ("SELECT name FROM account WHERE name = \"x\"", 39),
        ] {
            match parse(text) {
                Err(AppError::Validation(m)) => {
                    assert!(m.ends_with(&format!("at position {pos}")), "{text}: {m}")
                }
                other => panic!("{text}: {other:?}"),
            }
        }
        // Names are lower case; a keyword cannot be used as one.
        assert!(parse("SELECT Name FROM account").is_err());
        assert!(parse("SELECT from FROM account").is_err());
        assert!(
            parse(&format!(
                "SELECT name FROM account WHERE {}",
                "a = 1 AND ".repeat(60) + "a = 1"
            ))
            .is_err()
        );
        assert!(parse(&"x".repeat(MAX_TEXT_BYTES + 1)).is_err());
    }

    #[test]
    fn string_escape_is_literal_not_sql() {
        let parsed =
            parse("SELECT name FROM account WHERE name = 'O''Brien'' OR ''1''=''1'").unwrap();
        assert_eq!(
            parsed.r#where,
            Some(Condition::Compare {
                field: "name".into(),
                op: "eq".into(),
                value: Some(json!("O'Brien' OR '1'='1")),
            })
        );
        assert!(parse("SELECT name FROM account WHERE name = 'open").is_err());
    }
}
