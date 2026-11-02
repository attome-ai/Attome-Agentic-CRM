//! L8-T2: virtual entity providers (`attome_records::virtual_entity`) for an
//! outside Postgres table and an OData service, both read-only.
//!
//! - [`PostgresSource`]: one table or view of another Postgres database,
//!   reached with its own address (give it a read-only user; every session
//!   is also `default_transaction_read_only`). The key column must be a
//!   `uuid`: it is the record id. Filters on the configured columns become
//!   bound comparisons, each value cast to the column's own type (read once
//!   from `information_schema`); paging is by offset (`cursor` is the next
//!   offset).
//! - [`ODataSource`]: one entity set of an OData v4 service: `$filter`
//!   (eq, ne, gt, ge, lt, le, `contains`, `startswith`), `$orderby`, `$top`,
//!   `$skip` and `$select`. A key that is a GUID is the record id; any other
//!   key becomes a UUIDv5 of the set and key, remembered (at most
//!   [`KEY_MEMORY`]) so the record opens again by that id.
//!
//! SQL Server is not built: the workspace has no SQL Server driver.
//!
//! Register one for an entity with `attome_records::virtual_entity::register`
//! (an operator's boot code or an extension), naming its source address
//! from the deployment's secrets, never from request data.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use attome_core::filter::Filter;
use attome_records::virtual_entity::{BoxFut, VirtualPage, VirtualProvider, VirtualQuery};
use attome_types::AppError;
use serde_json::{Map, Value};
use uuid::Uuid;

/// Keys remembered for OData records whose key is not a GUID.
pub const KEY_MEMORY: usize = 50_000;
/// How long a source call may take.
const TIMEOUT: Duration = Duration::from_secs(20);

/// An outside identifier: letters, digits and `_`, not starting with a digit,
/// at most 63 characters. Pure.
pub fn outside_ident_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn quote(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn value_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

// ── Postgres ────────────────────────────────────────────────────────────────

/// The column types a filter value may be cast to.
const CASTABLE: [&str; 13] = [
    "smallint",
    "integer",
    "bigint",
    "numeric",
    "real",
    "double precision",
    "boolean",
    "text",
    "character varying",
    "uuid",
    "date",
    "timestamp without time zone",
    "timestamp with time zone",
];

/// One outside Postgres table.
pub struct PostgresSource {
    pool: sqlx::PgPool,
    table: String,
    key: String,
    columns: Vec<String>,
    types: tokio::sync::OnceCell<HashMap<String, String>>,
}

impl PostgresSource {
    /// A source over `table` at `url`, its record id the `uuid` column `key`
    /// and its fields `columns`. Nothing connects until the first read.
    pub fn new(url: &str, table: &str, key: &str, columns: &[&str]) -> Result<Self, AppError> {
        let names = std::iter::once(table)
            .chain(std::iter::once(key))
            .chain(columns.iter().copied());
        if let Some(bad) = names.into_iter().find(|n| !outside_ident_ok(n)) {
            return Err(AppError::Validation(format!(
                "{bad:?} is not a plain identifier"
            )));
        }
        let options: sqlx::postgres::PgConnectOptions = url
            .parse()
            .map_err(|_| AppError::Validation("the source address does not read".into()))?;
        let options = options.options([("default_transaction_read_only", "on")]);
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(TIMEOUT)
            .connect_lazy_with(options);
        Ok(PostgresSource {
            pool,
            table: table.to_owned(),
            key: key.to_owned(),
            columns: columns.iter().map(|c| (*c).to_owned()).collect(),
            types: tokio::sync::OnceCell::new(),
        })
    }

    async fn types(&self) -> Result<&HashMap<String, String>, AppError> {
        self.types
            .get_or_try_init(|| async {
                let rows: Vec<(String, String)> = sqlx::query_as(
                    "SELECT column_name::text, data_type::text FROM information_schema.columns \
                      WHERE table_name = $1",
                )
                .bind(&self.table)
                .fetch_all(&self.pool)
                .await
                .map_err(|_| AppError::CapabilityUnavailable("virtual_entity_source"))?;
                Ok::<_, AppError>(rows.into_iter().collect())
            })
            .await
    }

    /// The column a record field names: `id` is the key.
    fn column(&self, field: &str) -> Option<&str> {
        if field == "id" {
            return Some(&self.key);
        }
        self.columns
            .iter()
            .find(|c| *c == field)
            .map(String::as_str)
    }

    fn select_list(&self) -> String {
        std::iter::once(format!("{}::text AS \"id\"", quote(&self.key)))
            .chain(self.columns.iter().map(|c| quote(c)))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// One filter as SQL over the column `column` of type `ty`, its values bound
/// from `$first` on; the values to bind. Pure.
pub fn pg_condition(
    column: &str,
    ty: &str,
    filter: &Filter,
    first: usize,
) -> Option<(String, Vec<String>)> {
    let col = quote(column);
    let cast = if CASTABLE.contains(&ty) { ty } else { "text" };
    let one = |op: &str| {
        let value = filter.value.as_ref().map(value_text)?;
        Some((format!("{col} {op} ${first}::text::{cast}"), vec![value]))
    };
    match filter.op.as_str() {
        "eq" => one("="),
        "neq" => one("<>"),
        "gt" => one(">"),
        "gte" => one(">="),
        "lt" => one("<"),
        "lte" => one("<="),
        "is_null" => Some((format!("{col} IS NULL"), Vec::new())),
        "is_not_null" => Some((format!("{col} IS NOT NULL"), Vec::new())),
        "contains" | "starts_with" => {
            let value = filter.value.as_ref().map(value_text)?;
            let escaped = value
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            let pattern = if filter.op == "contains" {
                format!("%{escaped}%")
            } else {
                format!("{escaped}%")
            };
            Some((format!("{col}::text ILIKE ${first}"), vec![pattern]))
        }
        "in" => {
            let values: Vec<String> = filter
                .value
                .as_ref()?
                .as_array()?
                .iter()
                .map(value_text)
                .collect();
            Some((
                format!("{col} = ANY(${first}::text[]::{cast}[])"),
                vec![format!(
                    "{{{}}}",
                    values
                        .iter()
                        .map(|v| format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\"")))
                        .collect::<Vec<_>>()
                        .join(",")
                )],
            ))
        }
        _ => None,
    }
}

const PG_OPS: [&str; 10] = [
    "eq",
    "neq",
    "gt",
    "gte",
    "lt",
    "lte",
    "is_null",
    "is_not_null",
    "contains",
    "starts_with",
];

impl VirtualProvider for PostgresSource {
    fn supports(&self, field: &str, op: &str) -> bool {
        self.column(field).is_some() && (PG_OPS.contains(&op) || op == "in")
    }

    fn list<'a>(&'a self, query: &'a VirtualQuery) -> BoxFut<'a, Result<VirtualPage, AppError>> {
        Box::pin(async move {
            let types = self.types().await?;
            let mut clauses = Vec::new();
            let mut binds: Vec<String> = Vec::new();
            for filter in &query.filters {
                let column = self
                    .column(&filter.field)
                    .ok_or_else(|| AppError::Validation(format!("no field {}", filter.field)))?;
                let ty = types.get(column).map(String::as_str).unwrap_or("text");
                let (sql, values) =
                    pg_condition(column, ty, filter, binds.len() + 1).ok_or_else(|| {
                        AppError::Validation(format!("{} {}", filter.field, filter.op))
                    })?;
                clauses.push(sql);
                binds.extend(values);
            }
            let order = match &query.sort {
                Some((field, desc)) => match self.column(field) {
                    Some(column) => format!(
                        "{} {}, {}",
                        quote(column),
                        if *desc { "DESC" } else { "ASC" },
                        quote(&self.key)
                    ),
                    None => quote(&self.key),
                },
                None => quote(&self.key),
            };
            let offset: i64 = query
                .cursor
                .as_deref()
                .and_then(|c| c.parse().ok())
                .unwrap_or(0)
                .max(0);
            let limit = query.page_size.clamp(1, 200);
            let sql = format!(
                "SELECT row_to_json(r)::jsonb FROM (SELECT {} FROM {} {} ORDER BY {order} \
                 LIMIT {} OFFSET {offset}) r",
                self.select_list(),
                quote(&self.table),
                if clauses.is_empty() {
                    String::new()
                } else {
                    format!("WHERE {}", clauses.join(" AND "))
                },
                limit + 1,
            );
            let mut statement = sqlx::query_scalar::<_, Value>(&sql);
            for value in &binds {
                statement = statement.bind(value);
            }
            let rows = tokio::time::timeout(TIMEOUT, statement.fetch_all(&self.pool))
                .await
                .map_err(|_| AppError::CapabilityUnavailable("virtual_entity_source"))?
                .map_err(|_| AppError::CapabilityUnavailable("virtual_entity_source"))?;
            let more = i64::try_from(rows.len()).unwrap_or(0) > limit;
            let items = rows
                .into_iter()
                .take(usize::try_from(limit).unwrap_or(0))
                .filter_map(|row| row.as_object().cloned())
                .collect();
            Ok(VirtualPage {
                items,
                next_cursor: more.then(|| (offset + limit).to_string()),
            })
        })
    }

    fn get(&self, id: Uuid) -> BoxFut<'_, Result<Option<Map<String, Value>>, AppError>> {
        Box::pin(async move {
            let sql = format!(
                "SELECT row_to_json(r)::jsonb FROM (SELECT {} FROM {} WHERE {} = $1) r",
                self.select_list(),
                quote(&self.table),
                quote(&self.key)
            );
            let row: Option<Value> = tokio::time::timeout(
                TIMEOUT,
                sqlx::query_scalar(&sql).bind(id).fetch_optional(&self.pool),
            )
            .await
            .map_err(|_| AppError::CapabilityUnavailable("virtual_entity_source"))?
            .map_err(|_| AppError::CapabilityUnavailable("virtual_entity_source"))?;
            Ok(row.and_then(|r| r.as_object().cloned()))
        })
    }
}

// ── OData ───────────────────────────────────────────────────────────────────

/// A value as an OData literal: a GUID or number bare, `true`/`false`, a
/// string quoted with `'` doubled. Pure.
pub fn odata_literal(value: &Value) -> String {
    match value {
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::String(s) if Uuid::parse_str(s).is_ok() => s.clone(),
        Value::String(s) => format!("'{}'", s.replace('\'', "''")),
        Value::Null => "null".to_owned(),
        other => format!("'{}'", other.to_string().replace('\'', "''")),
    }
}

/// The `$filter` of `filters` over the field names `field_of` maps;
/// `None` when one cannot be expressed. Pure.
pub fn odata_filter(
    filters: &[Filter],
    field_of: impl Fn(&str) -> Option<String>,
) -> Option<String> {
    let mut parts = Vec::new();
    for filter in filters {
        let field = field_of(&filter.field)?;
        let value = || filter.value.as_ref().map(odata_literal);
        let part = match filter.op.as_str() {
            "eq" => format!("{field} eq {}", value()?),
            "neq" => format!("{field} ne {}", value()?),
            "gt" => format!("{field} gt {}", value()?),
            "gte" => format!("{field} ge {}", value()?),
            "lt" => format!("{field} lt {}", value()?),
            "lte" => format!("{field} le {}", value()?),
            "is_null" => format!("{field} eq null"),
            "is_not_null" => format!("{field} ne null"),
            "contains" => format!("contains({field},{})", value()?),
            "starts_with" => format!("startswith({field},{})", value()?),
            _ => return None,
        };
        parts.push(part);
    }
    Some(parts.join(" and "))
}

const ODATA_OPS: [&str; 10] = [
    "eq",
    "neq",
    "gt",
    "gte",
    "lt",
    "lte",
    "is_null",
    "is_not_null",
    "contains",
    "starts_with",
];

/// One OData entity set.
pub struct ODataSource {
    base_url: String,
    entity_set: String,
    key: String,
    fields: Vec<String>,
    headers: Vec<(String, String)>,
    http: attome_outbound::http::Outbound,
    keys: Arc<Mutex<HashMap<Uuid, Value>>>,
}

impl ODataSource {
    /// A source over `entity_set` of the service at `base_url` (an operator's
    /// address, internal ones allowed), its key field `key`, its fields
    /// `fields`, sending `headers` (an `Authorization`, say) on every call.
    pub fn new(
        base_url: &str,
        entity_set: &str,
        key: &str,
        fields: &[&str],
        headers: Vec<(String, String)>,
    ) -> Result<Self, AppError> {
        let names = std::iter::once(entity_set)
            .chain(std::iter::once(key))
            .chain(fields.iter().copied());
        if let Some(bad) = names.into_iter().find(|n| !outside_ident_ok(n)) {
            return Err(AppError::Validation(format!(
                "{bad:?} is not a plain identifier"
            )));
        }
        let purpose = attome_outbound::http::Purpose::public("odata-virtual-entity")
            .with_private_urls(std::iter::once(base_url))
            .no_redirects();
        let http = attome_outbound::http::client(purpose, |b| b.timeout(TIMEOUT))
            .map_err(|e| AppError::Validation(format!("the OData address: {e}")))?;
        Ok(ODataSource {
            base_url: base_url.trim_end_matches('/').to_owned(),
            entity_set: entity_set.to_owned(),
            key: key.to_owned(),
            fields: fields.iter().map(|f| (*f).to_owned()).collect(),
            headers,
            http,
            keys: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn field(&self, name: &str) -> Option<String> {
        if name == "id" {
            return Some(self.key.clone());
        }
        self.fields.iter().find(|f| *f == name).cloned()
    }

    /// The URL of a page. Pure apart from the fields.
    pub fn page_url(&self, query: &VirtualQuery) -> Option<String> {
        let mut params = vec![format!("$top={}", query.page_size.clamp(1, 200) + 1)];
        let skip: i64 = query
            .cursor
            .as_deref()
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        if skip > 0 {
            params.push(format!("$skip={skip}"));
        }
        let filter = odata_filter(&query.filters, |f| self.field(f))?;
        if !filter.is_empty() {
            params.push(format!("$filter={}", url_escape(&filter)));
        }
        if let Some((field, desc)) = &query.sort
            && let Some(field) = self.field(field)
        {
            params.push(format!(
                "$orderby={field}{}",
                if *desc { "%20desc" } else { "" }
            ));
        }
        let select = std::iter::once(self.key.clone())
            .chain(self.fields.iter().cloned())
            .collect::<Vec<_>>()
            .join(",");
        params.push(format!("$select={select}"));
        Some(format!(
            "{}/{}?{}",
            self.base_url,
            self.entity_set,
            params.join("&")
        ))
    }

    /// One OData row as a record: its key as the id. Remembers a key that is
    /// not a GUID.
    pub fn record(&self, row: &Map<String, Value>) -> Option<Map<String, Value>> {
        let key = row.get(&self.key)?;
        let id = match key.as_str().and_then(|s| Uuid::parse_str(s).ok()) {
            Some(id) => id,
            None => {
                let id = Uuid::new_v5(
                    &Uuid::NAMESPACE_URL,
                    format!(
                        "{}/{}({})",
                        self.base_url,
                        self.entity_set,
                        odata_literal(key)
                    )
                    .as_bytes(),
                );
                let mut keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
                if keys.len() >= KEY_MEMORY {
                    keys.clear();
                }
                keys.insert(id, key.clone());
                id
            }
        };
        let mut out = Map::new();
        out.insert("id".to_owned(), Value::String(id.to_string()));
        for field in &self.fields {
            out.insert(
                field.clone(),
                row.get(field).cloned().unwrap_or(Value::Null),
            );
        }
        Some(out)
    }

    async fn get_json(&self, url: &str) -> Result<Option<Value>, AppError> {
        let mut request = self.http.get(url).header("Accept", "application/json");
        for (name, value) in &self.headers {
            request = request.header(name.as_str(), value.as_str());
        }
        let answer = request
            .send()
            .await
            .map_err(|_| AppError::CapabilityUnavailable("virtual_entity_source"))?;
        if answer.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !answer.status().is_success() {
            return Err(AppError::CapabilityUnavailable("virtual_entity_source"));
        }
        answer
            .json::<Value>()
            .await
            .map(Some)
            .map_err(|_| AppError::CapabilityUnavailable("virtual_entity_source"))
    }
}

fn url_escape(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~'
            | b'('
            | b')'
            | b','
            | b'\'' => out.push(char::from(byte)),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

impl VirtualProvider for ODataSource {
    fn supports(&self, field: &str, op: &str) -> bool {
        self.field(field).is_some() && ODATA_OPS.contains(&op)
    }

    fn list<'a>(&'a self, query: &'a VirtualQuery) -> BoxFut<'a, Result<VirtualPage, AppError>> {
        Box::pin(async move {
            let url = self
                .page_url(query)
                .ok_or_else(|| AppError::Validation("a filter the source cannot take".into()))?;
            let body = self.get_json(&url).await?.unwrap_or(Value::Null);
            let rows: Vec<Map<String, Value>> = body["value"]
                .as_array()
                .map(|rows| rows.iter().filter_map(|r| r.as_object().cloned()).collect())
                .unwrap_or_default();
            let limit = usize::try_from(query.page_size.clamp(1, 200)).unwrap_or(50);
            let more = rows.len() > limit;
            let skip: i64 = query
                .cursor
                .as_deref()
                .and_then(|c| c.parse().ok())
                .unwrap_or(0);
            let items = rows
                .iter()
                .take(limit)
                .filter_map(|row| self.record(row))
                .collect();
            Ok(VirtualPage {
                items,
                next_cursor: more.then(|| (skip + i64::try_from(limit).unwrap_or(0)).to_string()),
            })
        })
    }

    fn get(&self, id: Uuid) -> BoxFut<'_, Result<Option<Map<String, Value>>, AppError>> {
        Box::pin(async move {
            let key = self
                .keys
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&id)
                .cloned()
                .unwrap_or_else(|| Value::String(id.to_string()));
            let url = format!(
                "{}/{}({})",
                self.base_url,
                self.entity_set,
                url_escape(&odata_literal(&key))
            );
            Ok(self
                .get_json(&url)
                .await?
                .and_then(|row| row.as_object().cloned())
                .and_then(|row| self.record(&row)))
        })
    }
}

/// The process-wide sources registered by name, for code that builds a
/// source once and registers it for several entities.
pub fn shared() -> &'static Mutex<HashMap<String, Arc<dyn VirtualProvider>>> {
    static SLOT: OnceLock<Mutex<HashMap<String, Arc<dyn VirtualProvider>>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn filter(field: &str, op: &str, value: Value) -> Filter {
        Filter {
            field: field.into(),
            op: op.into(),
            value: Some(value),
        }
    }

    #[test]
    fn odata_filters_and_literals() {
        let field_of = |f: &str| (f != "secret").then(|| f.to_owned());
        assert_eq!(
            odata_filter(
                &[
                    filter("Name", "contains", json!("O'Brien")),
                    filter("Amount", "gte", json!(10)),
                ],
                field_of,
            )
            .unwrap(),
            "contains(Name,'O''Brien') and Amount ge 10"
        );
        assert!(odata_filter(&[filter("secret", "eq", json!(1))], field_of).is_none());
        assert!(odata_filter(&[filter("Name", "under", json!(1))], field_of).is_none());
        let guid = "7f4f0b9e-2a4c-4f1e-9a51-0e2d6c3b1a77";
        assert_eq!(odata_literal(&json!(guid)), guid);
    }

    #[tokio::test]
    async fn odata_page_url_and_records() {
        let source = ODataSource::new(
            "https://erp.example.com/odata/",
            "Customers",
            "CustomerID",
            &["Name", "City"],
            Vec::new(),
        )
        .unwrap();
        let query = VirtualQuery {
            filters: vec![filter("City", "eq", json!("Riyadh"))],
            sort: Some(("Name".into(), true)),
            page_size: 20,
            cursor: Some("40".into()),
            select: None,
        };
        let url = source.page_url(&query).unwrap();
        assert!(
            url.starts_with("https://erp.example.com/odata/Customers?$top=21&$skip=40"),
            "{url}"
        );
        assert!(url.contains("$filter=City%20eq%20'Riyadh'"), "{url}");
        assert!(url.contains("$orderby=Name%20desc"), "{url}");
        let fixture =
            json!({ "CustomerID": "ALFKI", "Name": "Alfreds", "City": "Berlin", "Extra": 1 });
        let record = source.record(fixture.as_object().unwrap()).unwrap();
        let id: Uuid = record["id"].as_str().unwrap().parse().unwrap();
        assert_eq!(record["Name"], "Alfreds");
        assert!(record.get("Extra").is_none(), "only the configured fields");
        assert_eq!(
            source.keys.lock().unwrap().get(&id),
            Some(&json!("ALFKI")),
            "a non-GUID key is remembered for opening the record again"
        );
    }

    #[test]
    fn postgres_conditions_bind_and_cast() {
        let (sql, binds) =
            pg_condition("amount", "numeric", &filter("amount", "gt", json!(5)), 2).unwrap();
        assert_eq!(sql, "\"amount\" > $2::text::numeric");
        assert_eq!(binds, vec!["5"]);
        let (sql, binds) =
            pg_condition("name", "text", &filter("name", "contains", json!("50%")), 1).unwrap();
        assert_eq!(sql, "\"name\"::text ILIKE $1");
        assert_eq!(binds, vec!["%50\\%%"]);
        let (sql, _) =
            pg_condition("weird", "tsvector", &filter("weird", "eq", json!("x")), 1).unwrap();
        assert!(
            sql.ends_with("::text::text"),
            "an unknown type compares as text"
        );
        assert!(!outside_ident_ok("users; drop table x"));
        assert!(
            PostgresSource::new("postgres://ro@db/erp", "customers", "id", &["name; --"]).is_err()
        );
    }
}
