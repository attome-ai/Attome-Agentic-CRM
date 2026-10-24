//! Aggregate QuerySpecs (roadmap S4-T6): count, sum, avg, min, max and
//! count_distinct, grouped by fields and date buckets, with a having filter.
//! The WHERE, with every record-level predicate, applies before GROUP BY, so
//! a total never counts a record the caller cannot read, and a group key or
//! measured field goes through the same field gate as a selected one.
//!
//! What search/aggregate offers and this shape does not (for S4-T11): Hijri
//! month and year buckets, and an `other` bucket gathering the groups past
//! the limit.

use attome_core::{EntityMeta, quote_ident};
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde::Serialize;
use serde_json::{Map, Value};
use utoipa::ToSchema;

use super::compile::{Builder, Env, Scope};
use super::model::{AggFunc, Condition, DateBucket, QuerySpec};

/// The most groups one query returns; it fetches one more to tell.
pub const MAX_GROUPS: i64 = 1000;

/// A compiled aggregate query. Its rows hold the group keys as `g1…gN` and
/// the measures as `a1…aM`; [`CompiledAggregate::groups`] names them.
#[derive(Debug, Clone, PartialEq)]
pub struct CompiledAggregate {
    pub sql: String,
    pub binds: Vec<String>,
    /// The group fields, in `g1…` order.
    pub keys: Vec<String>,
    /// The aggregate aliases, in `a1…` order.
    pub aliases: Vec<String>,
}

/// One group of an aggregate result.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct Group {
    /// Each group field's value (a bucket's start for a date bucket).
    #[schema(value_type = Object)]
    pub keys: Map<String, Value>,
    /// Each aggregate's value, by alias.
    #[schema(value_type = Object)]
    pub values: Map<String, Value>,
}

/// An aggregate query's result.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct AggregateResult {
    pub groups: Vec<Group>,
}

impl CompiledAggregate {
    /// The result from the rows the SQL returned. More than [`MAX_GROUPS`]
    /// rows is the caller's to narrow.
    pub fn groups(&self, rows: Vec<Map<String, Value>>) -> Result<AggregateResult, AppError> {
        if i64::try_from(rows.len()).unwrap_or(i64::MAX) > MAX_GROUPS {
            return Err(AppError::Validation(
                "too many groups, narrow the query".into(),
            ));
        }
        let pick = |row: &Map<String, Value>, prefix: char, names: &[String]| {
            names
                .iter()
                .enumerate()
                .map(|(i, name)| {
                    let value = row
                        .get(&format!("{prefix}{}", i + 1))
                        .cloned()
                        .unwrap_or(Value::Null);
                    (name.clone(), value)
                })
                .collect::<Map<_, _>>()
        };
        Ok(AggregateResult {
            groups: rows
                .iter()
                .map(|row| Group {
                    keys: pick(row, 'g', &self.keys),
                    values: pick(row, 'a', &self.aliases),
                })
                .collect(),
        })
    }
}

fn bucket_unit(bucket: DateBucket) -> &'static str {
    match bucket {
        DateBucket::Day => "day",
        DateBucket::Week => "week",
        DateBucket::Month => "month",
        DateBucket::Quarter => "quarter",
        DateBucket::Year => "year",
    }
}

fn valid_alias(alias: &str) -> bool {
    let mut chars = alias.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && alias.len() <= 63
}

/// Compiles an aggregate `spec` for `env.ctx`.
pub fn compile(spec: &QuerySpec, env: &Env<'_>) -> Result<CompiledAggregate, AppError> {
    let root: &EntityMeta = env
        .registry
        .get(&spec.entity)
        .filter(|e| env.ctx.require(&e.logicalname, "read").is_ok())
        .ok_or(AppError::NotFound)?;
    if spec.aggregates.is_empty() {
        return Err(AppError::Validation(
            "an aggregate query needs at least one aggregate".into(),
        ));
    }
    if spec.cursor.is_some() {
        return Err(AppError::Validation(
            "an aggregate query has no pages; narrow it instead".into(),
        ));
    }
    let b = Builder::new(env);
    let scope = Scope::root(root);

    let mut select: Vec<String> = Vec::new();
    let mut keys: Vec<String> = Vec::new();
    let mut group_exprs: Vec<String> = Vec::new();
    let mut tz_param: Option<usize> = None;
    for (i, key) in spec.group_by.iter().enumerate() {
        let col = b.resolve(&scope, &key.field)?;
        let expr = match key.bucket {
            None => col.expr.clone(),
            Some(bucket) => {
                if col.cast != "timestamptz" {
                    return Err(AppError::Validation(format!(
                        "a date bucket needs a date field: {}",
                        key.field
                    )));
                }
                let tz = *tz_param.get_or_insert_with(|| b.bind(b.env().clock.tz.name()));
                format!(
                    "date_trunc('{}', {} AT TIME ZONE ${tz})",
                    bucket_unit(bucket),
                    col.expr
                )
            }
        };
        if keys.contains(&key.field) {
            return Err(AppError::Validation(format!(
                "grouped twice: {}",
                key.field
            )));
        }
        select.push(format!("{expr} AS g{}", i + 1));
        group_exprs.push(expr);
        keys.push(key.field.clone());
    }
    // A selected field is shown per group, so it must be one.
    for field in &spec.select {
        if !keys.contains(field) {
            return Err(AppError::Validation(format!(
                "a selected field must be grouped: {field}"
            )));
        }
    }

    let mut aliases: Vec<String> = Vec::new();
    let mut measures: Vec<String> = Vec::new();
    for (i, agg) in spec.aggregates.iter().enumerate() {
        if !valid_alias(&agg.alias) || aliases.contains(&agg.alias) || keys.contains(&agg.alias) {
            return Err(AppError::Validation(format!(
                "aggregate alias must be a new lower-case name: {}",
                agg.alias
            )));
        }
        let expr = match (agg.func, agg.field.as_deref()) {
            (AggFunc::Count, None) => "count(*)".to_owned(),
            (_, None) => {
                return Err(AppError::Validation(format!("{} needs a field", agg.alias)));
            }
            (func, Some(field)) => {
                let col = b.resolve(&scope, field)?;
                let numeric = col.cast == "numeric";
                let ok = match func {
                    AggFunc::Sum | AggFunc::Avg => numeric,
                    AggFunc::Min | AggFunc::Max => numeric || col.cast == "timestamptz",
                    AggFunc::Count | AggFunc::CountDistinct => true,
                };
                if !ok {
                    return Err(AppError::Validation(format!(
                        "{} cannot measure field: {field}",
                        agg.alias
                    )));
                }
                match func {
                    AggFunc::Count => format!("count({})", col.expr),
                    AggFunc::Sum => format!("sum({})", col.expr),
                    AggFunc::Avg => format!("avg({})", col.expr),
                    AggFunc::Min => format!("min({})", col.expr),
                    AggFunc::Max => format!("max({})", col.expr),
                    AggFunc::CountDistinct => format!("count(DISTINCT {})", col.expr),
                }
            }
        };
        select.push(format!("{expr} AS a{}", i + 1));
        measures.push(expr);
        aliases.push(agg.alias.clone());
    }

    let where_sql = match &spec.r#where {
        Some(condition) => format!(" AND {}", b.condition(&scope, condition, spec)?),
        None => String::new(),
    };
    let having_sql = match &spec.having {
        Some(condition) => format!(
            " HAVING {}",
            having(&b, condition, spec, &aliases, &measures)?
        ),
        None => String::new(),
    };
    // Order by the group keys unless the spec sorts by keys or aliases.
    let mut order: Vec<String> = Vec::new();
    for key in &spec.sort {
        let expr = if let Some(i) = keys.iter().position(|k| *k == key.field) {
            format!("g{}", i + 1)
        } else if let Some(i) = aliases.iter().position(|a| *a == key.field) {
            format!("a{}", i + 1)
        } else {
            return Err(AppError::Validation(format!(
                "an aggregate query sorts by a group field or an alias: {}",
                key.field
            )));
        };
        order.push(format!("{expr} {}", if key.desc { "DESC" } else { "ASC" }));
    }
    if order.is_empty() {
        order = (1..=keys.len()).map(|i| format!("g{i}")).collect();
    }
    let root_predicates = b.row_predicates(root, "t");

    let mut sql = format!(
        "SELECT {} FROM {} AS t{} WHERE TRUE{where_sql}{root_predicates}",
        select.join(", "),
        quote_ident(&root.logicalname),
        b.joins_sql(),
    );
    if !group_exprs.is_empty() {
        sql.push_str(&format!(" GROUP BY {}", group_exprs.join(", ")));
    }
    sql.push_str(&having_sql);
    if !order.is_empty() {
        sql.push_str(&format!(" ORDER BY {}", order.join(", ")));
    }
    sql.push_str(&format!(" LIMIT {}", MAX_GROUPS + 1));
    Ok(CompiledAggregate {
        sql,
        binds: b.into_binds(),
        keys,
        aliases,
    })
}

/// The having filter: comparisons of aggregate aliases with numbers.
/// PostgreSQL's HAVING cannot name an output alias, so the measure's own
/// expression is repeated.
fn having(
    b: &Builder<'_>,
    condition: &Condition,
    spec: &QuerySpec,
    aliases: &[String],
    measures: &[String],
) -> Result<String, AppError> {
    let parts = |items: &[Condition], sep: &str| -> Result<String, AppError> {
        let parts = items
            .iter()
            .map(|c| having(b, c, spec, aliases, measures))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(format!("({})", parts.join(sep)))
    };
    let compare = |field: &str, op: &str, value: Option<&Value>| -> Result<String, AppError> {
        let i = aliases.iter().position(|a| a == field).ok_or_else(|| {
            AppError::Validation(format!("having names an aggregate alias: {field}"))
        })?;
        let expr = &measures[i];
        let number = |v: &Value| -> Result<String, AppError> {
            match v {
                Value::Number(n) => Ok(n.to_string()),
                _ => Err(AppError::Validation(format!(
                    "having compares {field} with a number"
                ))),
            }
        };
        if op == "between" {
            let pair = value
                .and_then(Value::as_array)
                .filter(|v| v.len() == 2)
                .ok_or_else(|| {
                    AppError::Validation(format!("between takes two values: {field}"))
                })?;
            let low = b.bind(number(&pair[0])?);
            let high = b.bind(number(&pair[1])?);
            return Ok(format!(
                "({expr} >= ${low}::numeric AND {expr} <= ${high}::numeric)"
            ));
        }
        let sql_op = match op {
            "eq" => "=",
            "neq" => "<>",
            "gt" => ">",
            "gte" => ">=",
            "lt" => "<",
            "lte" => "<=",
            other => {
                return Err(AppError::Validation(format!(
                    "having does not take operator {other}"
                )));
            }
        };
        let value = value.ok_or_else(|| {
            AppError::Validation(format!("having compares {field} with a number"))
        })?;
        let n = b.bind(number(value)?);
        Ok(format!("{expr} {sql_op} ${n}::numeric"))
    };
    match condition {
        Condition::And { all } if all.is_empty() => Ok("TRUE".into()),
        Condition::Or { any } if any.is_empty() => Ok("FALSE".into()),
        Condition::And { all } => parts(all, " AND "),
        Condition::Or { any } => parts(any, " OR "),
        Condition::Not { condition } => Ok(format!(
            "(NOT ({}))",
            having(b, condition, spec, aliases, measures)?
        )),
        Condition::Compare { field, op, value } => compare(field, op, value.as_ref()),
        Condition::Param { field, op, param } => {
            let value = spec
                .params
                .get(param)
                .ok_or_else(|| AppError::Validation(format!("no value for parameter: {param}")))?;
            compare(field, op, Some(value))
        }
        Condition::Exists { .. } | Condition::NotExists { .. } => Err(AppError::Validation(
            "having takes comparisons of aggregates only".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use attome_core::RelationshipRegistry;
    use attome_server::security::{AccessLevel, SecurityContext};
    use serde_json::json;
    use uuid::Uuid;

    use super::super::compile::Access;
    use super::super::compile::fixtures::{
        clock, global, reader, registry, relationships, team_rls,
    };
    use super::*;

    fn run(
        doc: Value,
        ctx: &SecurityContext,
        access: &Access,
    ) -> Result<CompiledAggregate, AppError> {
        let registry = registry();
        let relationships: RelationshipRegistry = relationships();
        let mut clock = clock();
        clock.tz = "Asia/Riyadh".parse().unwrap();
        let env = Env {
            registry: &registry,
            relationships: &relationships,
            ctx,
            access,
            clock,
        };
        let spec: QuerySpec = serde_json::from_value(doc).expect("spec");
        compile(&spec, &env)
    }

    fn refused(doc: Value) -> String {
        match run(doc, &reader(), &global()) {
            Err(AppError::Validation(m)) => m,
            other => panic!("expected a validation error, got {other:?}"),
        }
    }

    #[test]
    fn count_group_by_month_uses_date_trunc_with_tz() {
        let c = run(
            json!({"entity": "account",
                   "group_by": [{"field": "created_on", "bucket": "month"}, {"field": "owner_ref"}],
                   "aggregates": [{"func": "count", "alias": "n"}]}),
            &reader(),
            &global(),
        )
        .unwrap();
        assert_eq!(
            c.sql,
            "SELECT date_trunc('month', t.\"created_on\" AT TIME ZONE $1) AS g1, t.\"owner_ref\" AS g2, \
             count(*) AS a1 FROM \"account\" AS t WHERE TRUE \
             AND (t.is_active IS NULL OR t.is_active = true) \
             GROUP BY date_trunc('month', t.\"created_on\" AT TIME ZONE $1), t.\"owner_ref\" \
             ORDER BY g1, g2 LIMIT 1001"
        );
        assert_eq!(c.binds, vec!["Asia/Riyadh".to_owned()]);
        assert_eq!(c.keys, vec!["created_on", "owner_ref"]);

        let rows = vec![
            json!({"g1": "2026-10-01T00:00:00", "g2": null, "a1": 3})
                .as_object()
                .unwrap()
                .clone(),
        ];
        let result = c.groups(rows).unwrap();
        assert_eq!(result.groups[0].values.get("n"), Some(&json!(3)));
        assert_eq!(result.groups[0].keys.get("owner_ref"), Some(&Value::Null));
        let too_many = vec![Map::new(); 1001];
        assert!(c.groups(too_many).is_err());
    }

    #[test]
    fn sum_on_text_is_rejected() {
        let m = refused(json!({"entity": "account",
            "aggregates": [{"func": "sum", "field": "name", "alias": "total"}]}));
        assert_eq!(m, "total cannot measure field: name");
        // A bucket needs a date, a measure an alias, and a field its grant.
        refused(
            json!({"entity": "account", "group_by": [{"field": "name", "bucket": "year"}],
            "aggregates": [{"func": "count", "alias": "n"}]}),
        );
        refused(json!({"entity": "account",
            "aggregates": [{"func": "count", "alias": "Bad Alias"}]}));
        assert_eq!(
            refused(
                json!({"entity": "account", "group_by": [{"field": "tax_id"}],
                "aggregates": [{"func": "count", "alias": "n"}]})
            ),
            "unknown attribute: tax_id"
        );
        refused(json!({"entity": "account", "select": ["name"],
            "aggregates": [{"func": "count", "alias": "n"}]}));
    }

    #[test]
    fn having_on_alias_compiles() {
        let c = run(
            json!({"entity": "account", "group_by": [{"field": "name"}],
                   "aggregates": [{"func": "sum", "field": "revenue", "alias": "total"},
                                  {"func": "count_distinct", "field": "owner_ref", "alias": "owners"}],
                   "having": {"kind": "and", "all": [
                       {"kind": "compare", "field": "total", "op": "gt", "value": 1000},
                       {"kind": "compare", "field": "owners", "op": "between", "value": [1, 5]}]},
                   "sort": [{"field": "total", "desc": true}]}),
            &reader(),
            &global(),
        )
        .unwrap();
        assert!(
            c.sql.contains(
                "GROUP BY t.\"name\" HAVING (sum(t.\"revenue\") > $1::numeric \
                 AND (count(DISTINCT t.\"owner_ref\") >= $2::numeric AND count(DISTINCT t.\"owner_ref\") <= $3::numeric)) \
                 ORDER BY a1 DESC LIMIT 1001"
            ),
            "{}",
            c.sql
        );
        assert_eq!(c.binds, vec!["1000", "1", "5"]);
        assert_eq!(
            refused(json!({"entity": "account", "group_by": [{"field": "name"}],
                "aggregates": [{"func": "count", "alias": "n"}],
                "having": {"kind": "compare", "field": "revenue", "op": "gt", "value": 1}})),
            "having names an aggregate alias: revenue"
        );
    }

    #[test]
    fn rls_is_in_where_before_group_by() {
        let team = global().with(Uuid::from_u128(1), AccessLevel::Team);
        let c = run(
            json!({"entity": "account", "group_by": [{"field": "owner_ref"}],
                   "aggregates": [{"func": "count", "alias": "open_cases"}],
                   "where": {"kind": "compare", "field": "revenue", "op": "gt", "value": 0}}),
            &reader(),
            &team,
        )
        .unwrap();
        let rls = team_rls(1, "t", 2);
        let where_at = c.sql.find(" WHERE ").unwrap();
        let rls_at = c.sql.find(&rls).expect("record-level predicate present");
        let group_at = c.sql.find(" GROUP BY ").unwrap();
        assert!(where_at < rls_at && rls_at < group_at, "{}", c.sql);
        assert_eq!(c.binds.len(), 7);
    }
}
