//! S6-T1: the GraphQL query language, as much of it as a read API needs:
//! one `query` operation (or the `{ … }` shorthand) with variables, fields,
//! aliases and arguments of every literal kind. Fragments, directives,
//! mutations and subscriptions are refused by name, so a client learns what
//! is not supported rather than getting a wrong answer.

use serde_json::{Map, Number, Value};

/// The longest query text read.
pub const MAX_QUERY_BYTES: usize = 32 * 1024;

/// One field of a selection set.
#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    /// The key the answer uses: the alias, or the name.
    pub alias: Option<String>,
    pub name: String,
    /// Arguments with variables already substituted.
    pub args: Vec<(String, Value)>,
    pub selection: Vec<Field>,
}

impl Field {
    /// The key this field answers under.
    pub fn key(&self) -> &str {
        self.alias.as_deref().unwrap_or(&self.name)
    }

    /// The argument `name`, if given.
    pub fn arg(&self, name: &str) -> Option<&Value> {
        self.args.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Name(String),
    Int(i64),
    Float(f64),
    Str(String),
    Punct(char),
    Spread,
}

fn lex(src: &str) -> Result<Vec<Token>, String> {
    let chars: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            ' ' | '\t' | '\n' | '\r' | ',' | '\u{feff}' => i += 1,
            '#' => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '{' | '}' | '(' | ')' | '[' | ']' | ':' | '$' | '!' | '=' | '@' | '|' | '&' => {
                out.push(Token::Punct(c));
                i += 1;
            }
            '.' => {
                if chars.get(i + 1) == Some(&'.') && chars.get(i + 2) == Some(&'.') {
                    out.push(Token::Spread);
                    i += 3;
                } else {
                    return Err(format!("unexpected '.' at {i}"));
                }
            }
            '"' => {
                if chars.get(i + 1) == Some(&'"') && chars.get(i + 2) == Some(&'"') {
                    return Err("block strings (\"\"\") are not supported".to_owned());
                }
                i += 1;
                let mut s = String::new();
                loop {
                    let Some(&ch) = chars.get(i) else {
                        return Err("unterminated string".to_owned());
                    };
                    i += 1;
                    match ch {
                        '"' => break,
                        '\n' => return Err("unterminated string".to_owned()),
                        '\\' => {
                            let Some(&esc) = chars.get(i) else {
                                return Err("unterminated string".to_owned());
                            };
                            i += 1;
                            match esc {
                                '"' => s.push('"'),
                                '\\' => s.push('\\'),
                                '/' => s.push('/'),
                                'b' => s.push('\u{8}'),
                                'f' => s.push('\u{c}'),
                                'n' => s.push('\n'),
                                'r' => s.push('\r'),
                                't' => s.push('\t'),
                                'u' => {
                                    let hex: String = chars.iter().skip(i).take(4).collect();
                                    let code = u32::from_str_radix(&hex, 16)
                                        .ok()
                                        .filter(|_| hex.len() == 4)
                                        .and_then(char::from_u32)
                                        .ok_or_else(|| format!("bad escape \\u{hex}"))?;
                                    s.push(code);
                                    i += 4;
                                }
                                other => return Err(format!("bad escape \\{other}")),
                            }
                        }
                        other => s.push(other),
                    }
                }
                out.push(Token::Str(s));
            }
            '-' | '0'..='9' => {
                let start = i;
                i += 1;
                while i < chars.len()
                    && (chars[i].is_ascii_digit()
                        || matches!(chars[i], '.' | 'e' | 'E' | '+' | '-'))
                {
                    i += 1;
                }
                let text: String = chars[start..i].iter().collect();
                if text.contains(['.', 'e', 'E']) {
                    out.push(Token::Float(
                        text.parse().map_err(|_| format!("bad number {text}"))?,
                    ));
                } else {
                    out.push(Token::Int(
                        text.parse().map_err(|_| format!("bad number {text}"))?,
                    ));
                }
            }
            c if c == '_' || c.is_ascii_alphabetic() => {
                let start = i;
                while i < chars.len() && (chars[i] == '_' || chars[i].is_ascii_alphanumeric()) {
                    i += 1;
                }
                out.push(Token::Name(chars[start..i].iter().collect()));
            }
            other => return Err(format!("unexpected character {other:?}")),
        }
    }
    Ok(out)
}

struct Parser<'a> {
    tokens: Vec<Token>,
    pos: usize,
    variables: &'a Map<String, Value>,
    /// Declared variables with their defaults.
    declared: Map<String, Value>,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn expect(&mut self, c: char) -> Result<(), String> {
        match self.next() {
            Some(Token::Punct(p)) if p == c => Ok(()),
            other => Err(format!(
                "expected '{c}', found {}",
                describe(other.as_ref())
            )),
        }
    }

    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(&Token::Punct(c)) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn name(&mut self) -> Result<String, String> {
        match self.next() {
            Some(Token::Name(n)) => Ok(n),
            other => Err(format!(
                "expected a name, found {}",
                describe(other.as_ref())
            )),
        }
    }

    fn refuse_directive(&self) -> Result<(), String> {
        if self.peek() == Some(&Token::Punct('@')) {
            return Err("directives are not supported".to_owned());
        }
        Ok(())
    }

    fn type_ref(&mut self) -> Result<(), String> {
        if self.eat('[') {
            self.type_ref()?;
            self.expect(']')?;
        } else {
            self.name()?;
        }
        self.eat('!');
        Ok(())
    }

    fn variable_definitions(&mut self) -> Result<(), String> {
        if !self.eat('(') {
            return Ok(());
        }
        while !self.eat(')') {
            self.expect('$')?;
            let name = self.name()?;
            self.expect(':')?;
            self.type_ref()?;
            let default = if self.eat('=') {
                self.value(true)?
            } else {
                Value::Null
            };
            self.declared.insert(name, default);
        }
        Ok(())
    }

    fn value(&mut self, constant: bool) -> Result<Value, String> {
        match self.next() {
            Some(Token::Punct('$')) if !constant => {
                let name = self.name()?;
                let Some(default) = self.declared.get(&name) else {
                    return Err(format!("variable ${name} is not declared"));
                };
                Ok(self
                    .variables
                    .get(&name)
                    .cloned()
                    .unwrap_or_else(|| default.clone()))
            }
            Some(Token::Int(n)) => Ok(Value::Number(n.into())),
            Some(Token::Float(f)) => Number::from_f64(f)
                .map(Value::Number)
                .ok_or_else(|| "a number out of range".to_owned()),
            Some(Token::Str(s)) => Ok(Value::String(s)),
            Some(Token::Name(n)) => Ok(match n.as_str() {
                "true" => Value::Bool(true),
                "false" => Value::Bool(false),
                "null" => Value::Null,
                _ => Value::String(n),
            }),
            Some(Token::Punct('[')) => {
                let mut items = Vec::new();
                while !self.eat(']') {
                    items.push(self.value(constant)?);
                }
                Ok(Value::Array(items))
            }
            Some(Token::Punct('{')) => {
                let mut fields = Map::new();
                while !self.eat('}') {
                    let key = self.name()?;
                    self.expect(':')?;
                    let v = self.value(constant)?;
                    fields.insert(key, v);
                }
                Ok(Value::Object(fields))
            }
            other => Err(format!(
                "expected a value, found {}",
                describe(other.as_ref())
            )),
        }
    }

    fn selection_set(&mut self, depth: usize) -> Result<Vec<Field>, String> {
        if depth > 32 {
            return Err("the query nests too deeply".to_owned());
        }
        self.expect('{')?;
        let mut fields = Vec::new();
        while !self.eat('}') {
            if self.peek() == Some(&Token::Spread) {
                return Err("fragments are not supported".to_owned());
            }
            let first = self.name()?;
            let (alias, name) = if self.eat(':') {
                (Some(first), self.name()?)
            } else {
                (None, first)
            };
            let mut args = Vec::new();
            if self.eat('(') {
                while !self.eat(')') {
                    let arg = self.name()?;
                    self.expect(':')?;
                    let v = self.value(false)?;
                    args.push((arg, v));
                }
            }
            self.refuse_directive()?;
            let selection = if self.peek() == Some(&Token::Punct('{')) {
                self.selection_set(depth + 1)?
            } else {
                Vec::new()
            };
            fields.push(Field {
                alias,
                name,
                args,
                selection,
            });
        }
        if fields.is_empty() {
            return Err("an empty selection set".to_owned());
        }
        Ok(fields)
    }
}

fn describe(t: Option<&Token>) -> String {
    match t {
        None => "the end of the query".to_owned(),
        Some(Token::Name(n)) => format!("'{n}'"),
        Some(Token::Int(n)) => n.to_string(),
        Some(Token::Float(f)) => f.to_string(),
        Some(Token::Str(_)) => "a string".to_owned(),
        Some(Token::Punct(c)) => format!("'{c}'"),
        Some(Token::Spread) => "'...'".to_owned(),
    }
}

/// Parses `src` into its one query's root fields, with `variables`
/// substituted. Pure.
pub fn parse_query(src: &str, variables: &Map<String, Value>) -> Result<Vec<Field>, String> {
    if src.len() > MAX_QUERY_BYTES {
        return Err(format!("the query is over {MAX_QUERY_BYTES} bytes"));
    }
    let mut p = Parser {
        tokens: lex(src)?,
        pos: 0,
        variables,
        declared: Map::new(),
    };
    let fields = match p.peek() {
        Some(Token::Punct('{')) => p.selection_set(0)?,
        Some(Token::Name(kw)) if kw == "query" => {
            p.next();
            if matches!(p.peek(), Some(Token::Name(_))) {
                p.next();
            }
            p.variable_definitions()?;
            p.refuse_directive()?;
            p.selection_set(0)?
        }
        Some(Token::Name(kw)) if kw == "mutation" || kw == "subscription" => {
            return Err(format!(
                "{kw} is not supported: this endpoint reads; write through the record API"
            ));
        }
        Some(Token::Name(kw)) if kw == "fragment" => {
            return Err("fragments are not supported".to_owned());
        }
        other => return Err(format!("expected a query, found {}", describe(other))),
    };
    if p.pos < p.tokens.len() {
        return Err("one operation per request".to_owned());
    }
    Ok(fields)
}

/// How deep the selection nests (a root field alone is 1). Pure.
pub fn depth(fields: &[Field]) -> usize {
    fields
        .iter()
        .map(|f| 1 + depth(&f.selection))
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vars(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap_or_default()
    }

    #[test]
    fn schema_query_parses_fields_aliases_arguments_and_variables() {
        let q = r#"
            query Deals($min: Float = 10, $who: String) {
              big: deal_list(where: { amount: { gte: $min }, owner: { eq: $who } }, first: 5, sort: "-amount") {
                items { id name account_ref { name } }
                next_cursor
              }
              # a comment
              account(id: "0190a0c2-0000-7000-8000-000000000001") { name __typename }
            }"#;
        let fields = parse_query(q, &vars(json!({ "who": "me" }))).unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].key(), "big");
        assert_eq!(fields[0].name, "deal_list");
        assert_eq!(
            fields[0].arg("where"),
            Some(&json!({ "amount": { "gte": 10 }, "owner": { "eq": "me" } }))
        );
        assert_eq!(fields[0].arg("first"), Some(&json!(5)));
        assert_eq!(
            fields[0].selection[0].selection[2].selection[0].name,
            "name"
        );
        assert_eq!(depth(&fields), 4);
        assert_eq!(fields[1].selection[1].name, "__typename");
    }

    #[test]
    fn schema_query_shorthand_lists_and_escapes() {
        let fields = parse_query(
            r#"{ a(x: [1, 2.5, true, null, RED], s: "q\"A") { b } }"#,
            &Map::new(),
        )
        .unwrap();
        assert_eq!(
            fields[0].arg("x"),
            Some(&json!([1, 2.5, true, null, "RED"]))
        );
        assert_eq!(fields[0].arg("s"), Some(&json!("q\"A")));
    }

    #[test]
    fn schema_query_refuses_what_it_does_not_support() {
        for (q, needle) in [
            ("mutation { a }", "mutation is not supported"),
            ("{ ...F }", "fragments"),
            ("{ a @include(if: true) }", "directives"),
            ("query { a(x: $y) }", "not declared"),
            ("{ a } { b }", "one operation"),
            ("{ }", "empty selection"),
            ("{ a(s: \"open) }", "unterminated"),
        ] {
            let err = parse_query(q, &Map::new()).unwrap_err();
            assert!(err.contains(needle), "{q}: {err}");
        }
        assert!(parse_query(&"{ a }".repeat(10_000), &Map::new()).is_err());
    }
}
