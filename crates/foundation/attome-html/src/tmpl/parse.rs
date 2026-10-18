//! The template parser (Z13-T2): text, `{{ expr }}` and `{% if %}` /
//! `{% for %}` blocks, each expression compiled against the schema in scope.

use std::collections::HashMap;

use attome_rules::{
    Budgets, Compiled, LanguageVersion, RulesError, Schema, Type, compile_versioned,
};

use super::{Position, TemplateError};

/// The most items one loop may name as its limit.
pub const MAX_LOOP_LIMIT: usize = 1_000;

#[derive(Debug, Clone)]
pub(crate) enum Node {
    Text(String),
    Output {
        at: Position,
        expr: Compiled,
    },
    If {
        at: Position,
        cond: Compiled,
        then: Vec<Node>,
        otherwise: Vec<Node>,
    },
    For {
        at: Position,
        var: String,
        list: Compiled,
        limit: usize,
        body: Vec<Node>,
    },
}

/// One piece of the source before the tree is built.
#[derive(Debug, Clone, PartialEq)]
enum Piece<'a> {
    Text(&'a str),
    Output { src: &'a str, at: usize },
    Tag { src: &'a str, at: usize },
}

fn syntax(source: &str, at: usize, message: impl Into<String>) -> TemplateError {
    TemplateError::Syntax {
        at: Position::of(source, at),
        message: message.into(),
    }
}

/// Splits `source` into text, outputs and tags.
fn pieces(source: &str) -> Result<Vec<Piece<'_>>, TemplateError> {
    let mut out = Vec::new();
    let mut rest = 0;
    while rest < source.len() {
        let tail = &source[rest..];
        let next = [tail.find("{{"), tail.find("{%")]
            .into_iter()
            .flatten()
            .min();
        let Some(open) = next else {
            out.push(Piece::Text(tail));
            break;
        };
        if open > 0 {
            out.push(Piece::Text(&tail[..open]));
        }
        let start = rest + open;
        let is_output = source[start..].starts_with("{{");
        let close = if is_output { "}}" } else { "%}" };
        let inner_start = start + 2;
        let Some(len) = source[inner_start..].find(close) else {
            return Err(syntax(
                source,
                start,
                format!("{} is never closed with {close}", &source[start..start + 2]),
            ));
        };
        let src = source[inner_start..inner_start + len].trim();
        out.push(if is_output {
            Piece::Output { src, at: start }
        } else {
            Piece::Tag { src, at: start }
        });
        rest = inner_start + len + 2;
    }
    Ok(out)
}

fn compile(source: &str, at: usize, src: &str, schema: &Schema) -> Result<Compiled, TemplateError> {
    if src.is_empty() {
        return Err(syntax(source, at, "an empty expression"));
    }
    compile_versioned(src, schema, LanguageVersion::V2, Budgets::default()).map_err(|error| {
        TemplateError::Expression {
            at: Position::of(source, at),
            error,
        }
    })
}

fn expression_error(source: &str, at: usize, message: String) -> TemplateError {
    TemplateError::Expression {
        at: Position::of(source, at),
        error: RulesError::Type(message),
    }
}

/// `for NAME in EXPR limit N`'s parts.
fn for_parts<'a>(
    source: &str,
    at: usize,
    rest: &'a str,
) -> Result<(&'a str, &'a str, usize), TemplateError> {
    let (var, after) = rest
        .trim()
        .split_once(char::is_whitespace)
        .ok_or_else(|| syntax(source, at, "a loop reads `for item in list limit N`"))?;
    let after = after.trim_start();
    let Some(after) = after
        .strip_prefix("in")
        .filter(|a| a.starts_with(char::is_whitespace))
    else {
        return Err(syntax(
            source,
            at,
            "a loop reads `for item in list limit N`",
        ));
    };
    let Some((list, limit)) = after.rsplit_once(" limit ") else {
        return Err(syntax(
            source,
            at,
            format!("a loop names its limit: `limit N`, N at most {MAX_LOOP_LIMIT}"),
        ));
    };
    let valid_name = var.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        && var
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if !valid_name {
        return Err(syntax(
            source,
            at,
            format!("{var:?} is not a loop item name"),
        ));
    }
    let limit: usize = limit.trim().parse().map_err(|_| {
        syntax(
            source,
            at,
            format!("{:?} is not a loop limit", limit.trim()),
        )
    })?;
    if limit == 0 || limit > MAX_LOOP_LIMIT {
        return Err(syntax(
            source,
            at,
            format!("a loop limit is 1 to {MAX_LOOP_LIMIT}, not {limit}"),
        ));
    }
    Ok((var, list.trim(), limit))
}

struct Builder<'a> {
    source: &'a str,
    pieces: Vec<Piece<'a>>,
    next: usize,
}

/// How a block ended.
enum End {
    Eof,
    Else(usize),
    End(usize),
}

impl Builder<'_> {
    /// Nodes until `{% else %}`, `{% end %}` or the end of the source.
    fn block(&mut self, schema: &Schema) -> Result<(Vec<Node>, End), TemplateError> {
        let mut nodes = Vec::new();
        while let Some(piece) = self.pieces.get(self.next).cloned() {
            self.next += 1;
            match piece {
                Piece::Text(text) => nodes.push(Node::Text(text.to_owned())),
                Piece::Output { src, at } => nodes.push(Node::Output {
                    at: Position::of(self.source, at),
                    expr: compile(self.source, at, src, schema)?,
                }),
                Piece::Tag { src, at } => {
                    let (word, rest) = src.split_once(char::is_whitespace).unwrap_or((src, ""));
                    match word {
                        "else" if rest.trim().is_empty() => return Ok((nodes, End::Else(at))),
                        "end" if rest.trim().is_empty() => return Ok((nodes, End::End(at))),
                        "if" => nodes.push(self.if_block(at, rest.trim(), schema)?),
                        "for" => nodes.push(self.for_block(at, rest, schema)?),
                        other => {
                            return Err(syntax(
                                self.source,
                                at,
                                format!("unknown tag {other:?} (if, else, for, end)"),
                            ));
                        }
                    }
                }
            }
        }
        Ok((nodes, End::Eof))
    }

    fn if_block(&mut self, at: usize, cond: &str, schema: &Schema) -> Result<Node, TemplateError> {
        let cond = compile(self.source, at, cond, schema)?;
        if cond.result_type().unify(&Type::Bool).is_none() {
            return Err(expression_error(
                self.source,
                at,
                format!("an if condition is a bool, not {}", cond.result_type()),
            ));
        }
        let (then, end) = self.block(schema)?;
        let otherwise = match end {
            End::End(_) => Vec::new(),
            End::Else(_) => match self.block(schema)? {
                (nodes, End::End(_)) => nodes,
                (_, End::Else(again)) => {
                    return Err(syntax(self.source, again, "a second {% else %} in one if"));
                }
                (_, End::Eof) => return Err(syntax(self.source, at, "this if has no {% end %}")),
            },
            End::Eof => return Err(syntax(self.source, at, "this if has no {% end %}")),
        };
        Ok(Node::If {
            at: Position::of(self.source, at),
            cond,
            then,
            otherwise,
        })
    }

    fn for_block(&mut self, at: usize, rest: &str, schema: &Schema) -> Result<Node, TemplateError> {
        let (var, list_src, limit) = for_parts(self.source, at, rest)?;
        let list = compile(self.source, at, list_src, schema)?;
        let elem = match list.result_type() {
            Type::List(elem) => (**elem).clone(),
            Type::Null => Type::Null,
            other => {
                return Err(expression_error(
                    self.source,
                    at,
                    format!("a loop runs over a list, not {other}"),
                ));
            }
        };
        let mut inner = schema.clone().with_field(var, elem.clone());
        if let Type::Record(fields) = &elem {
            inner = inner.with_related(
                var,
                fields.iter().cloned().collect::<HashMap<String, Type>>(),
            );
        }
        let body = match self.block(&inner)? {
            (nodes, End::End(_)) => nodes,
            (_, End::Else(other)) => {
                return Err(syntax(
                    self.source,
                    other,
                    "{% else %} belongs to an if, not a loop",
                ));
            }
            (_, End::Eof) => return Err(syntax(self.source, at, "this loop has no {% end %}")),
        };
        Ok(Node::For {
            at: Position::of(self.source, at),
            var: var.to_owned(),
            list,
            limit,
            body,
        })
    }
}

/// The template tree of `source`, compiled against `schema`.
pub(crate) fn parse(source: &str, schema: &Schema) -> Result<Vec<Node>, TemplateError> {
    let mut builder = Builder {
        source,
        pieces: pieces(source)?,
        next: 0,
    };
    match builder.block(schema)? {
        (nodes, End::Eof) => Ok(nodes),
        (_, End::Else(at)) => Err(syntax(source, at, "{% else %} outside an if")),
        (_, End::End(at)) => Err(syntax(source, at, "{% end %} with nothing to end")),
    }
}
