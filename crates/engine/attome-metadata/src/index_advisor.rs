//! Y2-T10: index proposals from slow queries. `pg_stat_statements` keeps
//! each normalised statement with its call count and mean time; a statement
//! that names an entity table and averages over [`SLOW_MEAN_MS`] is read for
//! the table's columns it filters on (a column before a comparison after
//! `WHERE`, `AND` or `OR`), and every such attribute that no index leads on
//! is proposed for a single-column index.
//!
//! A builder applies a proposal by making the attribute filterable
//! (`PATCH /api/v1/admin/entities/{entity_id}/fields/{field_id}` with
//! `is_filterable: true`), which builds the index `CONCURRENTLY` through the
//! index job and keeps it in the metadata, so a later reconcile does not
//! drop it. Nothing here writes.
//!
//! `pg_stat_statements` is optional: it needs `shared_preload_libraries`
//! and `CREATE EXTENSION pg_stat_statements` on the server, which an
//! operator chooses to enable. Without it the advice is empty and says why.

use std::collections::{BTreeMap, BTreeSet};

use attome_db::DbPool;
use attome_types::AppError;

/// A statement slower than this, on average, is read for proposals.
pub const SLOW_MEAN_MS: f64 = 100.0;

/// The slow statements read per entity.
const STATEMENT_SAMPLE: i64 = 50;

/// One proposed index.
#[derive(Debug, Clone, PartialEq)]
pub struct IndexProposal {
    pub attribute: String,
    /// Slow statements that filter on it.
    pub statements: i64,
    /// Their calls, summed.
    pub calls: i64,
    /// The slowest of their mean times, in milliseconds.
    pub worst_mean_ms: f64,
}

/// The proposals for one entity, or why there are none to give.
#[derive(Debug, Clone, PartialEq)]
pub enum Advice {
    Proposals(Vec<IndexProposal>),
    Unavailable(String),
}

const KEYWORDS: &[&str] = &["where", "and", "or", "not", "on"];
const OPERATORS: &[&str] = &[
    "=", "<", ">", "<=", ">=", "<>", "!=", "in", "like", "ilike", "is", "between", "@>", "&&",
];

/// The tokens of `sql`: identifiers (quotes removed, lower-cased),
/// operators, and one `?` per literal or parameter.
fn tokens(sql: &str) -> Vec<String> {
    let mut out = Vec::new();
    let chars: Vec<char> = sql.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() || matches!(c, '(' | ')' | ',' | ';') {
            i += 1;
        } else if c == '"' {
            let mut j = i + 1;
            let mut name = String::new();
            while j < chars.len() {
                if chars[j] == '"' {
                    if chars.get(j + 1) == Some(&'"') {
                        name.push('"');
                        j += 2;
                        continue;
                    }
                    break;
                }
                name.push(chars[j]);
                j += 1;
            }
            out.push(name.to_lowercase());
            i = j + 1;
        } else if c == '\'' {
            let mut j = i + 1;
            while j < chars.len() && chars[j] != '\'' {
                j += 1;
            }
            out.push("?".to_owned());
            i = j + 1;
        } else if c == '$' || c.is_ascii_digit() {
            let mut j = i + 1;
            while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '.') {
                j += 1;
            }
            out.push("?".to_owned());
            i = j;
        } else if c.is_alphanumeric() || c == '_' {
            let mut j = i;
            while j < chars.len() && (chars[j].is_alphanumeric() || chars[j] == '_') {
                j += 1;
            }
            out.push(chars[i..j].iter().collect::<String>().to_lowercase());
            i = j;
        } else if c == '.' {
            out.push(".".to_owned());
            i += 1;
        } else {
            let mut j = i;
            while j < chars.len() && "=<>!@&|:".contains(chars[j]) {
                j += 1;
            }
            if j == i {
                j += 1;
            }
            out.push(chars[i..j].iter().collect());
            i = j;
        }
    }
    out
}

/// The columns `sql` compares in its filters (`WHERE x = ?`, `AND t.y > ?`,
/// `OR "z" IN (...)`), lower-cased.
pub fn where_columns(sql: &str) -> BTreeSet<String> {
    let toks = tokens(sql);
    let mut out = BTreeSet::new();
    let mut in_filter = false;
    for (n, tok) in toks.iter().enumerate() {
        match tok.as_str() {
            "where" | "having" => in_filter = true,
            "group" | "order" | "limit" | "offset" | "returning" | "select" | "from" => {
                in_filter = false;
            }
            _ => {}
        }
        if !in_filter || KEYWORDS.contains(&tok.as_str()) || tok == "?" || tok == "." {
            continue;
        }
        let next = toks.get(n + 1).map(String::as_str);
        let qualifies = matches!(next, Some(op) if OPERATORS.contains(&op))
            || (next == Some("not")
                && matches!(
                    toks.get(n + 2).map(String::as_str),
                    Some("in" | "like" | "ilike")
                ));
        let is_name = tok
            .chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_');
        if qualifies && is_name {
            out.insert(tok.clone());
        }
    }
    out
}

/// Folds slow statements `(query, calls, mean ms)` into proposals for the
/// attributes in `attributes` that are not in `indexed`.
pub fn fold_proposals(
    entity: &str,
    statements: &[(String, i64, f64)],
    attributes: &BTreeSet<String>,
    indexed: &BTreeSet<String>,
) -> Vec<IndexProposal> {
    let mut by_attr: BTreeMap<String, IndexProposal> = BTreeMap::new();
    let entity = entity.to_lowercase();
    for (query, calls, mean) in statements {
        if !tokens(query).iter().any(|t| *t == entity) {
            continue;
        }
        for column in where_columns(query) {
            if !attributes.contains(&column) || indexed.contains(&column) {
                continue;
            }
            let p = by_attr.entry(column.clone()).or_insert(IndexProposal {
                attribute: column,
                statements: 0,
                calls: 0,
                worst_mean_ms: 0.0,
            });
            p.statements += 1;
            p.calls = p.calls.saturating_add(*calls);
            p.worst_mean_ms = p.worst_mean_ms.max(*mean);
        }
    }
    let mut out: Vec<IndexProposal> = by_attr.into_values().collect();
    out.sort_by(|a, b| {
        b.calls
            .cmp(&a.calls)
            .then_with(|| a.attribute.cmp(&b.attribute))
    });
    out
}

/// The proposals for `entity`, whose attributes are `attributes`.
pub async fn proposals(
    db: &DbPool,
    entity: &str,
    attributes: &BTreeSet<String>,
) -> Result<Advice, AppError> {
    let installed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements')",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !installed {
        return Ok(Advice::Unavailable(
            "pg_stat_statements not installed".to_owned(),
        ));
    }
    let statements: Vec<(String, i64, f64)> = match sqlx::query_as(
        "SELECT query, calls, mean_exec_time FROM pg_stat_statements \
          WHERE mean_exec_time > $2 AND strpos(lower(query), lower($1)) > 0 \
          ORDER BY mean_exec_time DESC LIMIT $3",
    )
    .bind(entity)
    .bind(SLOW_MEAN_MS)
    .bind(STATEMENT_SAMPLE)
    .fetch_all(db)
    .await
    {
        Ok(rows) => rows,
        // Created but not preloaded: the view refuses to answer.
        Err(error) => {
            tracing::warn!(%error, "index advisor: pg_stat_statements is not readable");
            return Ok(Advice::Unavailable(
                "pg_stat_statements is not loaded (shared_preload_libraries)".to_owned(),
            ));
        }
    };
    let indexed: BTreeSet<String> = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT a.attname::text FROM pg_index i \
         JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0] \
         WHERE i.indrelid = to_regclass(format('%I', $1::text))",
    )
    .bind(entity)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .collect();
    Ok(Advice::Proposals(fold_proposals(
        entity,
        &statements,
        attributes,
        &indexed,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_where_columns() {
        let sql = r#"SELECT row_to_json(t.*) FROM (SELECT * FROM "deal" WHERE "deal"."stage" = $1 AND amount > $2 OR t.owner_ref IN ($3, $4) AND "Region" NOT LIKE $5) t ORDER BY name LIMIT $6"#;
        let cols = where_columns(sql);
        for c in ["stage", "amount", "owner_ref", "region"] {
            assert!(cols.contains(c), "{c} in {cols:?}");
        }
        assert!(!cols.contains("name"), "ORDER BY is not a filter: {cols:?}");
        assert!(!cols.contains("deal"));
        assert!(where_columns("SELECT a FROM b").is_empty());
        assert!(where_columns("UPDATE x SET y = $1 WHERE id = $2").contains("id"));
    }

    #[test]
    fn folds_unindexed_attributes_by_calls() {
        let attrs: BTreeSet<String> = ["stage", "amount", "id"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let indexed: BTreeSet<String> = ["id"].iter().map(|s| (*s).to_owned()).collect();
        let statements = vec![
            ("SELECT 1 FROM deal WHERE stage = $1".to_owned(), 10, 150.0),
            (
                "SELECT 1 FROM deal WHERE stage = $1 AND amount > $2".to_owned(),
                5,
                300.0,
            ),
            ("SELECT 1 FROM deal WHERE id = $1".to_owned(), 99, 500.0),
            (
                "SELECT 1 FROM other WHERE stage = $1".to_owned(),
                1_000,
                900.0,
            ),
        ];
        let out = fold_proposals("deal", &statements, &attrs, &indexed);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].attribute, "stage");
        assert_eq!(
            (out[0].statements, out[0].calls, out[0].worst_mean_ms),
            (2, 15, 300.0)
        );
        assert_eq!(out[1].attribute, "amount");
    }
}
