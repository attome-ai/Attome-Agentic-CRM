//! A30-T2: environment variables (A30-T1's `environment_variable` kind) in
//! rule and flow expressions, as `env.<name>`.
//!
//! [`context`] is the object rules see under `env`: every non-secret
//! variable this deployment's published metadata defines, with the value
//! the deployment set (`environment_variable_value`) or else the
//! definition's default, `null` when neither. A secret is never in it: a
//! rule cannot read or leak one; a connector reads its secrets through the
//! credential path.
//!
//! [`missing`] is the publish check: an expression that names a variable
//! that is not defined, is a secret, or is required with no value and no
//! default cannot be published.

use std::collections::{BTreeMap, BTreeSet};

use attome_db::DbPool;
use attome_types::AppError;
use serde_json::{Map, Value};

/// One published definition, as rules need it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnvDef {
    pub required: bool,
    pub secret: bool,
    pub default: Option<Value>,
}

impl EnvDef {
    /// Reads a published `environment_variable` document.
    pub fn from_doc(doc: &Value) -> Self {
        Self {
            required: doc
                .get("required")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            secret: doc.get("type").and_then(Value::as_str) == Some("secret"),
            default: doc.get("default").filter(|v| !v.is_null()).cloned(),
        }
    }
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The variable names `src` reads as `env.<name>`. Text in quotes is
/// skipped, and so is `env` that is part of a longer name. Pure.
pub fn references(src: &str) -> BTreeSet<String> {
    let chars: Vec<char> = src.chars().collect();
    let mut out = BTreeSet::new();
    let mut quote: Option<char> = None;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if let Some(q) = quote {
            if c == '\\' {
                i += 2;
                continue;
            }
            if c == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        if c == '"' || c == '\'' {
            quote = Some(c);
            i += 1;
            continue;
        }
        let starts_word = i == 0 || !(is_name_char(chars[i - 1]) || chars[i - 1] == '.');
        if starts_word && chars[i..].starts_with(&['e', 'n', 'v', '.']) {
            let mut j = i + 4;
            let name: String = chars[j..]
                .iter()
                .take_while(|c| is_name_char(**c))
                .collect();
            j += name.chars().count();
            if !name.is_empty() && name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
                out.insert(name);
            }
            i = j;
            continue;
        }
        i += 1;
    }
    out
}

/// Why each referenced variable cannot be read, as messages; empty when
/// every one can. `set` names the variables this deployment gave a value.
/// Pure.
pub fn missing(
    refs: &BTreeSet<String>,
    defs: &BTreeMap<String, EnvDef>,
    set: &BTreeSet<String>,
) -> Vec<String> {
    refs.iter()
        .filter_map(|name| match defs.get(name) {
            None => Some(format!("env.{name} is not a defined environment variable")),
            Some(def) if def.secret => Some(format!(
                "env.{name} is a secret; rules and flows cannot read secrets"
            )),
            Some(def) if def.required && def.default.is_none() && !set.contains(name) => Some(
                format!("env.{name} is required and has no value on this deployment"),
            ),
            Some(_) => None,
        })
        .collect()
}

/// The `env` object rules read. Pure.
pub fn context(defs: &BTreeMap<String, EnvDef>, values: &BTreeMap<String, Value>) -> Value {
    let mut env = Map::new();
    for (name, def) in defs.iter().filter(|(_, d)| !d.secret) {
        let value = values
            .get(name)
            .or(def.default.as_ref())
            .cloned()
            .unwrap_or(Value::Null);
        env.insert(name.clone(), value);
    }
    Value::Object(env)
}

/// `input` with `env` beside its fields (a non-object input is kept as
/// `value`), unless it already has one. Pure.
pub fn with_env(input: &Value, env: Value) -> Value {
    match input {
        Value::Object(fields) if fields.contains_key("env") => input.clone(),
        Value::Object(fields) => {
            let mut out = fields.clone();
            out.insert("env".into(), env);
            Value::Object(out)
        }
        other => {
            let mut out = Map::new();
            out.insert("value".into(), other.clone());
            out.insert("env".into(), env);
            Value::Object(out)
        }
    }
}

/// The published definitions and this deployment's non-secret values.
pub async fn load(
    db: &DbPool,
) -> Result<(BTreeMap<String, EnvDef>, BTreeMap<String, Value>), AppError> {
    let docs: Vec<(String, Value)> = sqlx::query_as(
        "SELECT DISTINCT ON (o.id) o.name, v.doc \
           FROM metadata_object o \
           JOIN metadata_object_version v ON v.object_id = o.id \
          WHERE o.kind = 'environment_variable' AND o.is_active AND v.state = 'published' \
          ORDER BY o.id, v.version_no DESC",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let defs: BTreeMap<String, EnvDef> = docs
        .into_iter()
        .map(|(name, doc)| (name, EnvDef::from_doc(&doc)))
        .collect();
    let values: Vec<(String, Value)> = sqlx::query_as(
        "SELECT name, value FROM environment_variable_value WHERE value IS NOT NULL",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok((defs, values.into_iter().collect()))
}

/// The names this deployment set a value for, secrets included.
pub async fn names_set(db: &DbPool) -> Result<BTreeSet<String>, AppError> {
    let names: Vec<String> = sqlx::query_scalar("SELECT name FROM environment_variable_value")
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
    Ok(names.into_iter().collect())
}

/// The `env` object for this deployment, read now.
pub async fn context_for(db: &DbPool) -> Result<Value, AppError> {
    let (defs, values) = load(db).await?;
    Ok(context(&defs, &values))
}

/// Refuses an expression set that reads a variable it cannot (publish).
pub async fn check_publish<'a>(
    db: &DbPool,
    expressions: impl IntoIterator<Item = &'a str>,
) -> Result<(), AppError> {
    let refs: BTreeSet<String> = expressions.into_iter().flat_map(references).collect();
    if refs.is_empty() {
        return Ok(());
    }
    let (defs, _) = load(db).await?;
    let problems = missing(&refs, &defs, &names_set(db).await?);
    if problems.is_empty() {
        Ok(())
    } else {
        Err(AppError::Validation(problems.join("; ")))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn defs() -> BTreeMap<String, EnvDef> {
        BTreeMap::from([
            (
                "erp_url".to_owned(),
                EnvDef::from_doc(&json!({"type": "url", "required": true})),
            ),
            (
                "region".to_owned(),
                EnvDef::from_doc(&json!({"type": "text", "default": "SA"})),
            ),
            (
                "api_key".to_owned(),
                EnvDef::from_doc(&json!({"type": "secret", "required": true})),
            ),
            (
                "limit".to_owned(),
                EnvDef::from_doc(&json!({"type": "number"})),
            ),
        ])
    }

    #[test]
    fn env_lookup_references_skip_quotes_and_longer_names() {
        let refs = references(
            "record.amount > env.limit && env.region == 'env.not_this' && myenv.x == 1 && record.env.y",
        );
        assert_eq!(
            refs,
            BTreeSet::from(["limit".to_owned(), "region".to_owned()])
        );
        assert!(references("amount > 5").is_empty());
        assert!(references("env.").is_empty());
    }

    #[test]
    fn env_lookup_context_uses_value_then_default_and_hides_secrets() {
        let values = BTreeMap::from([("erp_url".to_owned(), json!("https://erp.example.sa"))]);
        let env = context(&defs(), &values);
        assert_eq!(env["erp_url"], "https://erp.example.sa");
        assert_eq!(env["region"], "SA");
        assert_eq!(env["limit"], Value::Null);
        assert!(
            env.get("api_key").is_none(),
            "a secret is never in the context"
        );
    }

    #[test]
    fn env_lookup_missing_values_fail_publish() {
        let refs = BTreeSet::from([
            "erp_url".to_owned(),
            "region".to_owned(),
            "api_key".to_owned(),
            "nope".to_owned(),
        ]);
        let problems = missing(&refs, &defs(), &BTreeSet::new());
        assert_eq!(problems.len(), 3, "{problems:?}");
        assert!(
            problems
                .iter()
                .any(|p| p.contains("env.erp_url is required"))
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("env.api_key is a secret"))
        );
        assert!(problems.iter().any(|p| p.contains("env.nope is not")));
        let set = BTreeSet::from(["erp_url".to_owned()]);
        assert_eq!(
            missing(&BTreeSet::from(["erp_url".to_owned()]), &defs(), &set),
            Vec::<String>::new()
        );
    }

    #[test]
    fn env_lookup_with_env_keeps_the_input() {
        let env = json!({"region": "SA"});
        assert_eq!(
            with_env(&json!({"amount": 5}), env.clone()),
            json!({"amount": 5, "env": {"region": "SA"}})
        );
        assert_eq!(
            with_env(&json!(7), env.clone()),
            json!({"value": 7, "env": {"region": "SA"}})
        );
        let own = json!({"env": "mine"});
        assert_eq!(with_env(&own, env), own);
    }
}
