//! OData system query options to a QuerySpec. Pure.
//!
//! Read: `$select`, `$filter` ([`super::filter`]), `$orderby`, `$top`,
//! `$skiptoken` (the next page, as the server's own `@odata.nextLink`
//! gives it), `$count` and `$format=json`. Refused with a message naming the
//! option: `$expand`, `$search`, `$apply`, `$compute`, `$levels`, any other
//! `$` option, and a non-zero `$skip` (offset paging is not offered; follow
//! `@odata.nextLink`). Options without a `$` are custom options and ignored,
//! as the protocol says.

use crate::query_spec::{QuerySpec, SortKey};

/// The rows one page holds unless `$top` asks for fewer.
pub const PAGE_SIZE: i64 = crate::query_spec::compile::MAX_PAGE_SIZE;

/// A request's options, read.
#[derive(Debug, Clone, PartialEq)]
pub struct Options {
    pub spec: QuerySpec,
    /// `$count=true`: answer the total too.
    pub count: bool,
    /// `$select` was given (else every readable attribute is chosen).
    pub selected: bool,
    /// `$top`, when it asks for fewer rows than a page: no next page then.
    pub top: Option<i64>,
}

fn paths(list: &str, what: &str) -> Result<Vec<String>, String> {
    list.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| {
            let parts: Vec<&str> = p.split('/').collect();
            let ok = parts.len() <= 4
                && parts.iter().all(|s| {
                    s.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                });
            if ok {
                Ok(parts.join("."))
            } else {
                Err(format!("{p:?} is not a field in {what}"))
            }
        })
        .collect()
}

/// Reads the query options of a request on `entity`. `pairs` are the
/// decoded query string pairs, in order.
pub fn read(entity: &str, pairs: &[(String, String)]) -> Result<Options, String> {
    let mut spec = QuerySpec {
        entity: entity.to_owned(),
        select: Vec::new(),
        r#where: None,
        sort: Vec::new(),
        page_size: Some(PAGE_SIZE),
        cursor: None,
        group_by: Vec::new(),
        aggregates: Vec::new(),
        having: None,
        explain: false,
        as_of: None,
        params: Default::default(),
        totals: None,
    };
    let mut count = false;
    let mut selected = false;
    let mut top = None;
    let mut seen = std::collections::BTreeSet::new();
    for (name, value) in pairs {
        if !name.starts_with('$') {
            continue;
        }
        if !seen.insert(name.as_str()) {
            return Err(format!("{name} is given more than once"));
        }
        match name.as_str() {
            "$select" => {
                if value.trim() != "*" {
                    spec.select = paths(value, "$select")?;
                    selected = !spec.select.is_empty();
                }
            }
            "$filter" => spec.r#where = Some(super::filter::parse(value)?),
            "$orderby" => {
                for item in value.split(',').map(str::trim).filter(|i| !i.is_empty()) {
                    let mut words = item.split_whitespace();
                    let field = words.next().unwrap_or_default();
                    let desc = match words.next() {
                        None | Some("asc") => false,
                        Some("desc") => true,
                        Some(other) => {
                            return Err(format!("{other:?} is not asc or desc in $orderby"));
                        }
                    };
                    if words.next().is_some() {
                        return Err(format!("{item:?} is not a field and a direction"));
                    }
                    let field = paths(field, "$orderby")?.remove(0);
                    spec.sort.push(SortKey { field, desc });
                }
            }
            "$top" => {
                let n: i64 = value
                    .trim()
                    .parse()
                    .map_err(|_| "$top is a whole number".to_owned())?;
                if n < 0 {
                    return Err("$top is a whole number".into());
                }
                if n < PAGE_SIZE {
                    spec.page_size = Some(n.max(1));
                    top = Some(n);
                }
            }
            "$skip" => {
                if value.trim() != "0" {
                    return Err(
                        "$skip is not supported: follow @odata.nextLink for the next page".into(),
                    );
                }
            }
            "$skiptoken" => spec.cursor = Some(value.clone()),
            "$count" => match value.trim() {
                "true" => count = true,
                "false" => {}
                _ => return Err("$count is true or false".into()),
            },
            "$format" => {
                let format = value.trim().to_ascii_lowercase();
                if format != "json" && !format.starts_with("application/json") {
                    return Err("$format is json: the service answers JSON only".into());
                }
            }
            "$expand" => {
                return Err(
                    "$expand is not supported: select a lookup's id, or a related field as a/b"
                        .into(),
                );
            }
            other => return Err(format!("{other} is not supported")),
        }
    }
    Ok(Options {
        spec,
        count,
        selected,
        top,
    })
}

/// The query string of the next page: the request's own `$` options with
/// `$skiptoken` replaced. Custom options are dropped.
pub fn next_query(pairs: &[(String, String)], token: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = pairs
        .iter()
        .filter(|(k, _)| k.starts_with('$') && k != "$skiptoken")
        .cloned()
        .collect();
    out.push(("$skiptoken".into(), token.to_owned()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn odata_options_power_bi_first_request() {
        // What Power BI sends for a table preview.
        let o = read(
            "account",
            &pairs(&[
                ("$select", "id,name,city"),
                ("$filter", "city eq 'Riyadh'"),
                ("$orderby", "name desc, id"),
                ("$top", "1000"),
            ]),
        )
        .unwrap();
        assert_eq!(o.spec.select, vec!["id", "name", "city"]);
        assert!(o.spec.r#where.is_some());
        assert_eq!(
            o.spec.sort,
            vec![
                SortKey {
                    field: "name".into(),
                    desc: true
                },
                SortKey {
                    field: "id".into(),
                    desc: false
                }
            ]
        );
        // A $top above a page still pages through nextLink.
        assert_eq!(o.spec.page_size, Some(PAGE_SIZE));
        assert_eq!(o.top, None);
        assert!(o.selected);
    }

    #[test]
    fn odata_options_excel_paging_and_count() {
        let o = read(
            "contact",
            &pairs(&[
                ("$count", "true"),
                ("$skiptoken", "abc"),
                ("$top", "10"),
                ("x", "1"),
            ]),
        )
        .unwrap();
        assert!(o.count);
        assert_eq!(o.spec.cursor.as_deref(), Some("abc"));
        assert_eq!(o.spec.page_size, Some(10));
        assert_eq!(o.top, Some(10));
        assert!(!o.selected);
        let next = next_query(
            &pairs(&[("$top", "10"), ("$skiptoken", "abc"), ("x", "1")]),
            "def",
        );
        assert_eq!(next, pairs(&[("$top", "10"), ("$skiptoken", "def")]));
    }

    #[test]
    fn odata_options_refused_clearly() {
        for (k, v) in [
            ("$expand", "contacts"),
            ("$skip", "20"),
            ("$search", "x"),
            ("$apply", "groupby((city))"),
            ("$format", "xml"),
            ("$orderby", "name sideways"),
            ("$select", "name;drop"),
            ("$top", "-1"),
            ("$count", "maybe"),
        ] {
            assert!(read("account", &pairs(&[(k, v)])).is_err(), "{k}={v}");
        }
        assert!(read("account", &pairs(&[("$skip", "0"), ("$format", "json")])).is_ok());
        assert!(read("account", &pairs(&[("$top", "1"), ("$top", "2")])).is_err());
    }
}
