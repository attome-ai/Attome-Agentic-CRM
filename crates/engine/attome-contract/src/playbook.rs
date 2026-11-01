//! Contract playbook checks (roadmap W1-T5): every enabled
//! `contract_playbook_rule` judged on each save of a contract or one of its
//! clauses, inside the save's transaction (`attome_core::record_check`).
//!
//! A rule's `condition` is an `attome-rules` expression; when it comes out
//! true the contract deviates from the playbook. A rule without a
//! `clause_key` is judged once, over the contract's fields, for example
//! `contract_value > 1000000`. A rule with a `clause_key` is judged once for
//! each of the contract's clauses whose library clause carries that key,
//! over the contract's fields plus the clause's own, prefixed `clause_`
//! (`clause_title`, `clause_body_html`, `clause_position`, ...); a contract
//! without such a clause does not deviate from it. A rule with no condition
//! says nothing.
//!
//! Severity `info` and `needs_legal` record a deviation; `block` refuses the
//! save with a 422 naming the clause and the rule's message. A condition
//! that does not compile or does not come out a boolean records a
//! `needs_legal` deviation carrying the error and never blocks: a broken
//! rule sends the contract to legal rather than stopping every save.
//!
//! Conditions see every attribute, sensitive ones included: rules are
//! written by administrators and a deviation carries the rule's message,
//! never a field's value.
//!
//! The deviations are written to the contract's engine-managed
//! `playbook_deviations` (JSON text; empty when none): with the save itself
//! when the contract is saved, and by this engine when a clause is. Rules
//! are read from their table on every save, in the save's transaction, so
//! there is no cache to invalidate; they are bounded by [`MAX_RULES`] and a
//! contract's clauses by [`MAX_CLAUSES`]. A deleted clause updates the
//! deviations at the contract's next save.

use std::collections::HashSet;

use attome_core::EngineState;
use attome_core::record_check::{RecordCheck, RecordCheckFuture, RecordSave};
use attome_types::AppError;
use serde::Serialize;
use serde_json::{Map, Value};
use sqlx::PgConnection;
use uuid::Uuid;

/// The most rules one save is judged against.
pub const MAX_RULES: i64 = 500;
/// The most clauses of one contract one save reads.
pub const MAX_CLAUSES: i64 = 500;
/// The contract attribute the deviations are written to.
pub const DEVIATIONS_FIELD: &str = "playbook_deviations";

/// How much a deviation matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    NeedsLegal,
    Block,
}

impl Severity {
    /// The rule's stored choice; anything unknown is `info`.
    pub fn parse(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            Some("block") => Self::Block,
            Some("needs_legal") => Self::NeedsLegal,
            _ => Self::Info,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::NeedsLegal => "needs_legal",
            Self::Block => "block",
        }
    }
}

/// One playbook rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: Uuid,
    pub clause_key: Option<String>,
    pub condition: Option<String>,
    pub severity: Severity,
    pub message: Option<String>,
    pub message_ar: Option<String>,
}

/// One of the contract's clauses: its library key and its own fields.
#[derive(Debug, Clone)]
pub struct Clause {
    pub id: Uuid,
    pub clause_key: Option<String>,
    pub fields: Map<String, Value>,
}

/// One way the contract departs from the playbook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Deviation {
    pub rule_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clause_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_clause_id: Option<Uuid>,
    pub severity: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_ar: Option<String>,
    /// Set when the rule's condition could not be judged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Whether `condition` holds over `payload`: `Ok(true)` deviates,
/// `Err` when it does not compile or is not a boolean. A field in `known`
/// (an attribute of the contract or the clause) that this record leaves
/// empty is not in the payload: the condition then cannot hold. Pure.
fn holds(condition: &str, payload: &Value, known: &HashSet<String>) -> Result<bool, String> {
    let (schema, ctx) = attome_audit::approval::schema_and_context_for_payload(payload);
    let compiled = match attome_rules::compile(condition, &schema) {
        Ok(compiled) => compiled,
        Err(attome_rules::RulesError::UnknownField(field)) if known.contains(&field) => {
            return Ok(false);
        }
        Err(e) => return Err(e.to_string()),
    };
    match compiled.eval(&ctx) {
        Ok(attome_rules::Value::Bool(b)) => Ok(b),
        Ok(_) => Err("the condition is not true or false".to_owned()),
        Err(e) => Err(e.to_string()),
    }
}

fn deviation(rule: &Rule, clause: Option<&Clause>, error: Option<String>) -> Deviation {
    let severity = if error.is_some() {
        Severity::NeedsLegal
    } else {
        rule.severity
    };
    Deviation {
        rule_id: rule.id,
        clause_key: rule.clause_key.clone(),
        contract_clause_id: clause.map(|c| c.id),
        severity: severity.as_str(),
        message: rule.message.clone(),
        message_ar: rule.message_ar.clone(),
        error,
    }
}

/// Every deviation of `contract` with `clauses` from `rules`. `known` names
/// every field a condition may use (contract attributes, and clause
/// attributes as `clause_<name>`), set or not. Pure.
pub fn check(
    contract: &Map<String, Value>,
    clauses: &[Clause],
    rules: &[Rule],
    known: &HashSet<String>,
) -> Vec<Deviation> {
    let mut out = Vec::new();
    for rule in rules {
        let Some(condition) = rule
            .condition
            .as_deref()
            .map(str::trim)
            .filter(|c| !c.is_empty())
        else {
            continue;
        };
        let key = rule
            .clause_key
            .as_deref()
            .map(str::trim)
            .filter(|k| !k.is_empty());
        let Some(key) = key else {
            let payload = Value::Object(contract.clone());
            match holds(condition, &payload, known) {
                Ok(true) => out.push(deviation(rule, None, None)),
                Ok(false) => {}
                Err(e) => out.push(deviation(rule, None, Some(e))),
            }
            continue;
        };
        for clause in clauses
            .iter()
            .filter(|c| c.clause_key.as_deref().map(str::trim) == Some(key))
        {
            let mut payload = contract.clone();
            for (field, value) in &clause.fields {
                payload.insert(format!("clause_{field}"), value.clone());
            }
            payload.insert("clause_key".to_owned(), Value::String(key.to_owned()));
            match holds(condition, &Value::Object(payload), known) {
                Ok(true) => out.push(deviation(rule, Some(clause), None)),
                Ok(false) => {}
                Err(e) => out.push(deviation(rule, Some(clause), Some(e))),
            }
        }
    }
    out
}

/// The 422 for the first blocking deviation, naming the clause and the
/// rule's message.
pub fn refusal(deviations: &[Deviation], clauses: &[Clause]) -> Option<AppError> {
    let blocking = deviations
        .iter()
        .find(|d| d.severity == Severity::Block.as_str() && d.error.is_none())?;
    let message = blocking
        .message
        .clone()
        .unwrap_or_else(|| "the contract breaks a playbook rule".to_owned());
    let clause = blocking.contract_clause_id.and_then(|id| {
        clauses.iter().find(|c| c.id == id).map(|c| {
            c.fields
                .get("title")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| c.clause_key.clone())
                .unwrap_or_else(|| id.to_string())
        })
    });
    Some(AppError::Validation(match clause {
        Some(clause) => format!("Playbook: clause '{clause}': {message}"),
        None => format!("Playbook: {message}"),
    }))
}

/// The deviations as stored on the contract: JSON text, `None` when none.
pub fn stored(deviations: &[Deviation]) -> Result<Option<String>, AppError> {
    if deviations.is_empty() {
        return Ok(None);
    }
    serde_json::to_string(deviations)
        .map(Some)
        .map_err(AppError::internal)
}

/// What the registry says about the entities a check reads, taken before
/// any `.await` (a registry guard is not held across one).
struct Shape {
    /// The contract has the deviations attribute.
    stores: bool,
    contract_fields: HashSet<String>,
    clause_fields: HashSet<String>,
    /// The pack's clause tables and the rule table are all installed.
    complete: bool,
}

fn shape(state: &EngineState) -> Shape {
    let registry = state.entities.load();
    let attributes = |entity: &str| -> HashSet<String> {
        registry
            .get(entity)
            .map(|meta| {
                meta.attrs
                    .iter()
                    .filter(|a| a.logicalname != DEVIATIONS_FIELD)
                    .map(|a| a.logicalname.clone())
                    .collect()
            })
            .unwrap_or_default()
    };
    let stores = registry
        .get("contract")
        .is_some_and(|m| m.attrs.iter().any(|a| a.logicalname == DEVIATIONS_FIELD));
    let complete = [
        "contract",
        "contract_clause",
        "clause",
        "contract_playbook_rule",
    ]
    .iter()
    .all(|e| registry.get(e).is_some());
    Shape {
        stores,
        contract_fields: attributes("contract"),
        clause_fields: attributes("contract_clause"),
        complete,
    }
}

impl Shape {
    /// Every field a condition may name.
    fn known(&self) -> HashSet<String> {
        let mut known = self.contract_fields.clone();
        known.extend(self.clause_fields.iter().map(|f| format!("clause_{f}")));
        known.insert("clause_key".to_owned());
        known
    }
}

/// Keeps the attribute values of a row read as JSON.
fn attribute_values(row: Value, fields: &HashSet<String>) -> Map<String, Value> {
    match row {
        Value::Object(map) => map
            .into_iter()
            .filter(|(k, _)| fields.contains(k))
            .collect(),
        _ => Map::new(),
    }
}

type RuleRow = (
    Uuid,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

async fn load_rules(conn: &mut PgConnection) -> Result<Vec<Rule>, AppError> {
    let rows: Vec<RuleRow> = sqlx::query_as(
        "SELECT id, clause_key, condition, severity, message, message_ar \
           FROM contract_playbook_rule \
          WHERE is_active IS DISTINCT FROM false \
          ORDER BY id LIMIT $1",
    )
    .bind(MAX_RULES)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(
            |(id, clause_key, condition, severity, message, message_ar)| Rule {
                id,
                clause_key,
                condition,
                severity: Severity::parse(severity.as_deref()),
                message,
                message_ar,
            },
        )
        .collect())
}

async fn load_contract(
    conn: &mut PgConnection,
    id: Uuid,
    fields: &HashSet<String>,
) -> Result<Option<Map<String, Value>>, AppError> {
    let row: Option<(Value,)> = sqlx::query_as(
        "SELECT to_jsonb(c) FROM contract c WHERE c.id = $1 AND c.is_active IS DISTINCT FROM false",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(row.map(|(v,)| attribute_values(v, fields)))
}

async fn load_clauses(
    conn: &mut PgConnection,
    contract: Uuid,
    fields: &HashSet<String>,
) -> Result<Vec<Clause>, AppError> {
    let rows: Vec<(Uuid, Value, Option<String>)> = sqlx::query_as(
        "SELECT cc.id, to_jsonb(cc), cl.clause_key \
           FROM contract_clause cc \
           LEFT JOIN clause cl ON cl.id = cc.clause_ref AND cl.is_active IS DISTINCT FROM false \
          WHERE cc.contract_ref = $1 AND cc.is_active IS DISTINCT FROM false \
          ORDER BY cc.position NULLS LAST, cc.id LIMIT $2",
    )
    .bind(contract)
    .bind(MAX_CLAUSES)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(id, row, clause_key)| Clause {
            id,
            clause_key,
            fields: attribute_values(row, fields),
        })
        .collect())
}

async fn clause_key_of(conn: &mut PgConnection, clause: Uuid) -> Result<Option<String>, AppError> {
    let row: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT clause_key FROM clause WHERE id = $1 AND is_active IS DISTINCT FROM false",
    )
    .bind(clause)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(row.and_then(|(k,)| k))
}

fn uuid_of(body: &Map<String, Value>, field: &str) -> Option<Option<Uuid>> {
    body.get(field)
        .map(|v| v.as_str().and_then(|s| Uuid::parse_str(s.trim()).ok()))
}

/// A contract save: the stored contract with the submitted fields over it,
/// judged with its stored clauses; the deviations go into the body.
async fn on_contract(
    conn: &mut PgConnection,
    state: &EngineState,
    save: RecordSave<'_>,
) -> Result<Option<Map<String, Value>>, AppError> {
    let shape = shape(state);
    if !shape.complete {
        return Ok(None);
    }
    let rules = load_rules(conn).await?;
    let (mut contract, clauses) = match save.record_id {
        Some(id) => (
            load_contract(conn, id, &shape.contract_fields)
                .await?
                .unwrap_or_default(),
            load_clauses(conn, id, &shape.clause_fields).await?,
        ),
        None => (Map::new(), Vec::new()),
    };
    for (k, v) in save.body {
        if shape.contract_fields.contains(k) {
            contract.insert(k.clone(), v.clone());
        }
    }
    let deviations = check(&contract, &clauses, &rules, &shape.known());
    if let Some(refused) = refusal(&deviations, &clauses) {
        return Err(refused);
    }
    if !shape.stores {
        return Ok(None);
    }
    let mut filled = Map::new();
    filled.insert(
        DEVIATIONS_FIELD.to_owned(),
        stored(&deviations)?.map_or(Value::Null, Value::String),
    );
    Ok(Some(filled))
}

/// A clause save: the clause's contract judged with its clauses, this one
/// as submitted; the deviations are written to the contract.
async fn on_clause(
    conn: &mut PgConnection,
    state: &EngineState,
    save: RecordSave<'_>,
) -> Result<Option<Map<String, Value>>, AppError> {
    let shape = shape(state);
    if !shape.complete {
        return Ok(None);
    }
    // The stored clause, when this is an update.
    let stored_clause: Option<(Value, Option<Uuid>, Option<Uuid>)> = match save.record_id {
        Some(id) => sqlx::query_as(
            "SELECT to_jsonb(cc), cc.contract_ref, cc.clause_ref FROM contract_clause cc WHERE cc.id = $1",
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(AppError::internal)?,
        None => None,
    };
    let contract_id = match uuid_of(save.body, "contract_ref") {
        Some(named) => named,
        None => stored_clause.as_ref().and_then(|(_, c, _)| *c),
    };
    let Some(contract_id) = contract_id else {
        return Ok(None);
    };
    let Some(contract) = load_contract(conn, contract_id, &shape.contract_fields).await? else {
        return Ok(None);
    };
    let library = match uuid_of(save.body, "clause_ref") {
        Some(named) => named,
        None => stored_clause.as_ref().and_then(|(_, _, l)| *l),
    };
    let clause_key = match library {
        Some(id) => clause_key_of(conn, id).await?,
        None => None,
    };
    let mut fields = stored_clause
        .map(|(row, _, _)| attribute_values(row, &shape.clause_fields))
        .unwrap_or_default();
    for (k, v) in save.body {
        if shape.clause_fields.contains(k) {
            fields.insert(k.clone(), v.clone());
        }
    }
    let this_id = save.record_id.unwrap_or_else(Uuid::nil);
    let mut clauses: Vec<Clause> = load_clauses(conn, contract_id, &shape.clause_fields)
        .await?
        .into_iter()
        .filter(|c| c.id != this_id)
        .collect();
    clauses.push(Clause {
        id: this_id,
        clause_key,
        fields,
    });
    let rules = load_rules(conn).await?;
    let deviations = check(&contract, &clauses, &rules, &shape.known());
    if let Some(refused) = refusal(&deviations, &clauses) {
        return Err(refused);
    }
    if shape.stores {
        // An engine-managed attribute, written beside the clause in the
        // same transaction; unchanged values are not rewritten.
        sqlx::query(
            "UPDATE contract SET playbook_deviations = $1 \
              WHERE id = $2 AND playbook_deviations IS DISTINCT FROM $1",
        )
        .bind(stored(&deviations)?)
        .bind(contract_id)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(None)
}

/// W1-T12: a contract's deviations from the playbook as `security` reads
/// it (the contract through the caller's read, its clauses once the caller
/// may read clauses), each with the fallback clauses the library offers for
/// its clause key. Writes nothing.
pub async fn review(
    state: &EngineState,
    security: &attome_server::security::SecurityContext,
    contract_id: Uuid,
) -> Result<Value, AppError> {
    use attome_security::SecurityContextExt;
    let shape = shape(state);
    if !shape.complete {
        return Err(AppError::NotFound);
    }
    let record =
        attome_records::entity_crud::read_record(state, security, "contract", contract_id).await?;
    let contract = attribute_values(record.data().clone(), &shape.contract_fields);
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let clauses = if security.require("contract_clause", "read").is_ok() {
        load_clauses(&mut conn, contract_id, &shape.clause_fields).await?
    } else {
        Vec::new()
    };
    let rules = load_rules(&mut conn).await?;
    let deviations = check(&contract, &clauses, &rules, &shape.known());
    let mut out = Vec::with_capacity(deviations.len());
    for deviation in deviations {
        let fallbacks: Vec<String> = match deviation.clause_key.as_deref() {
            Some(key) if security.require("clause", "read").is_ok() => sqlx::query_scalar(
                "SELECT f.title FROM clause f JOIN clause c ON f.fallback_of_ref = c.id \
                  WHERE c.clause_key = $1 AND f.title IS NOT NULL \
                    AND f.is_active IS DISTINCT FROM false AND c.is_active IS DISTINCT FROM false \
                  ORDER BY f.title LIMIT 10",
            )
            .bind(key)
            .fetch_all(&mut *conn)
            .await
            .map_err(AppError::internal)?,
            _ => Vec::new(),
        };
        let mut value = serde_json::to_value(&deviation).map_err(AppError::internal)?;
        value["fallbacks"] = serde_json::json!(fallbacks);
        out.push(value);
    }
    Ok(serde_json::json!({ "contract_id": contract_id, "deviations": out }))
}

/// The save-time playbook check, registered for `contract` and
/// `contract_clause` by `ContractModel::record_checks`.
#[derive(Debug)]
pub struct PlaybookCheck;

impl RecordCheck for PlaybookCheck {
    fn check<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        state: &'a EngineState,
        save: RecordSave<'a>,
    ) -> RecordCheckFuture<'a> {
        Box::pin(async move {
            match save.entity {
                "contract" => on_contract(conn, state, save).await,
                "contract_clause" => on_clause(conn, state, save).await,
                _ => Ok(None),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rule(clause_key: Option<&str>, condition: &str, severity: Severity) -> Rule {
        Rule {
            id: Uuid::now_v7(),
            clause_key: clause_key.map(str::to_owned),
            condition: Some(condition.to_owned()),
            severity,
            message: Some("Liability cap below the limit".to_owned()),
            message_ar: None,
        }
    }

    fn clause(key: &str, fields: Value) -> Clause {
        Clause {
            id: Uuid::now_v7(),
            clause_key: Some(key.to_owned()),
            fields: fields.as_object().cloned().unwrap_or_default(),
        }
    }

    fn contract(fields: Value) -> Map<String, Value> {
        fields.as_object().cloned().unwrap_or_default()
    }

    fn none() -> HashSet<String> {
        HashSet::new()
    }

    #[test]
    fn an_empty_attribute_does_not_deviate_but_a_typo_goes_to_legal() {
        let rules = [rule(None, "contract_value > 5", Severity::Block)];
        let known: HashSet<String> = ["contract_value".to_owned()].into_iter().collect();
        assert!(check(&contract(json!({})), &[], &rules, &known).is_empty());
        let typo = check(&contract(json!({})), &[], &rules, &none());
        assert_eq!(typo.len(), 1);
        assert_eq!(typo[0].severity, "needs_legal");
    }

    #[test]
    fn liability_cap_below_limit_needs_legal() {
        let rules = [rule(
            Some("liability"),
            "clause_cap < 1000000",
            Severity::NeedsLegal,
        )];
        let clauses = [clause(
            "liability",
            json!({ "title": "Liability", "cap": 250000 }),
        )];
        let found = check(
            &contract(json!({ "title": "MSA" })),
            &clauses,
            &rules,
            &none(),
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, "needs_legal");
        assert_eq!(found[0].contract_clause_id, Some(clauses[0].id));
        assert!(
            refusal(&found, &clauses).is_none(),
            "needs_legal never blocks"
        );

        let fine = [clause("liability", json!({ "cap": 5000000 }))];
        assert!(check(&contract(json!({})), &fine, &rules, &none()).is_empty());
        // No clause with the key: nothing to judge.
        assert!(check(&contract(json!({})), &[], &rules, &none()).is_empty());
    }

    #[test]
    fn block_rule_rejects_save() {
        let rules = [rule(None, "contract_value > 1000000", Severity::Block)];
        let found = check(
            &contract(json!({ "contract_value": 2000000 })),
            &[],
            &rules,
            &none(),
        );
        assert_eq!(found.len(), 1);
        match refusal(&found, &[]) {
            Some(AppError::Validation(message)) => {
                assert!(
                    message.contains("Liability cap below the limit"),
                    "{message}"
                );
            }
            other => panic!("expected a validation refusal, got {other:?}"),
        }
        assert!(
            check(
                &contract(json!({ "contract_value": 10 })),
                &[],
                &rules,
                &none()
            )
            .is_empty()
        );
    }

    #[test]
    fn a_broken_rule_goes_to_legal_and_never_blocks() {
        let rules = [rule(None, "contract_value >", Severity::Block)];
        let found = check(
            &contract(json!({ "contract_value": 1 })),
            &[],
            &rules,
            &none(),
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, "needs_legal");
        assert!(found[0].error.is_some());
        assert!(refusal(&found, &[]).is_none());
        assert_eq!(stored(&[]).unwrap(), None);
        assert!(stored(&found).unwrap().unwrap().starts_with('['));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore)]
    fn check_under_10ms_for_50_rules() {
        let rules: Vec<Rule> = (0..50)
            .map(|i| {
                rule(
                    Some("liability"),
                    &format!("clause_cap < {} and contract_value > {i}", 1000 * i),
                    Severity::NeedsLegal,
                )
            })
            .collect();
        let clauses: Vec<Clause> = (0..5)
            .map(|i| clause("liability", json!({ "cap": 1000 * i })))
            .collect();
        let started = std::time::Instant::now();
        let found = check(
            &contract(json!({ "contract_value": 100 })),
            &clauses,
            &rules,
            &none(),
        );
        let elapsed = started.elapsed();
        assert!(!found.is_empty());
        assert!(
            elapsed < std::time::Duration::from_millis(10),
            "took {elapsed:?}"
        );
    }
}
