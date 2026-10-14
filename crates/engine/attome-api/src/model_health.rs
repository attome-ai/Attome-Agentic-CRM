//! `GET /api/v1/admin/model/health` (roadmap A1-T11): what the data model
//! has that nobody uses or that looks wrong, for an administrator or the
//! model-health agent to act on.
//!
//! Every finding comes from the entity registry and PostgreSQL's own
//! statistics, never from reading records:
//!
//! - **broken references:** a lookup whose target entity is unknown or gone;
//! - **duplicate-looking attributes:** two attributes of one entity whose
//!   names collapse to the same words (`email` and `e_mail`, `phone_no` and
//!   `phone_number`);
//! - **unused entities:** a table with no live rows (`pg_stat_user_tables`);
//! - **unused attributes:** a column every analysed row leaves empty
//!   (`pg_stats.null_frac = 1`, so only after the table has been analysed);
//! - **index proposals:** a filterable attribute no index starts with.
//!
//! Findings are proposals: nothing here changes the model.

use std::collections::{BTreeMap, HashSet};

use attome_core::{EngineState, EntityMeta, FieldType};
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;
use utoipa::ToSchema;

/// The most findings of one kind one report returns.
const MAX_FINDINGS: usize = 500;

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct Finding {
    /// `broken_reference`, `duplicate_attribute`, `unused_entity`,
    /// `unused_attribute` or `index_proposal`.
    pub kind: String,
    pub entity: String,
    /// The attribute, when the finding is about one.
    pub attribute: Option<String>,
    pub detail: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ModelHealth {
    pub entities: usize,
    pub findings: Vec<Finding>,
}

/// An attribute name reduced to its words, for spotting duplicates: lower
/// case, separators and common abbreviations folded.
pub fn name_key(name: &str) -> String {
    let words: Vec<String> = name
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| {
            match w {
                "no" | "num" | "nbr" => "number",
                "addr" => "address",
                "tel" | "telephone" | "mobile" => "phone",
                "mail" => "email",
                "desc" => "description",
                "qty" => "quantity",
                "amt" => "amount",
                "dt" => "date",
                other => other,
            }
            .to_owned()
        })
        .collect();
    words.join("").replace("emailaddress", "email")
}

/// The registry-only findings for one entity: broken references and
/// duplicate-looking attributes.
pub fn registry_findings(meta: &EntityMeta, known: &HashSet<uuid::Uuid>) -> Vec<Finding> {
    let mut out = Vec::new();
    for attr in &meta.attrs {
        if attr.field_type() == FieldType::Lookup {
            let broken = attr
                .lookup_entity_ref
                .is_none_or(|target| !known.contains(&target));
            if broken {
                out.push(Finding {
                    kind: "broken_reference".into(),
                    entity: meta.logicalname.clone(),
                    attribute: Some(attr.logicalname.clone()),
                    detail: "the lookup's target entity is unknown or gone".into(),
                });
            }
        }
    }
    let mut by_key: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for attr in &meta.attrs {
        if attome_core::ALL_SYSTEM_COLS.contains(&attr.logicalname.as_str()) {
            continue;
        }
        by_key
            .entry(name_key(&attr.logicalname))
            .or_default()
            .push(&attr.logicalname);
    }
    for names in by_key.values().filter(|names| names.len() > 1) {
        out.push(Finding {
            kind: "duplicate_attribute".into(),
            entity: meta.logicalname.clone(),
            attribute: Some(names.join(", ")),
            detail: "these attributes look like the same thing".into(),
        });
    }
    out
}

/// `GET /api/v1/admin/model/health`
#[utoipa::path(
    get,
    path = "/api/v1/admin/model/health",
    tag = "admin",
    responses(
        (status = 200, description = "Model-health findings", body = ModelHealth),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn model_health(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<ModelHealth>, AppError> {
    let (entities, mut findings, filterable) = {
        let registry = state.entities.load();
        let known: HashSet<uuid::Uuid> = registry.iter().map(|m| m.entity_id).collect();
        let mut findings = Vec::new();
        let mut filterable: Vec<(String, String)> = Vec::new();
        for meta in registry.iter() {
            findings.extend(registry_findings(meta, &known));
            for attr in meta.attrs.iter().filter(|a| a.is_filterable) {
                filterable.push((meta.logicalname.clone(), attr.logicalname.clone()));
            }
        }
        (registry.len(), findings, filterable)
    };
    let names: Vec<String> = {
        let registry = state.entities.load();
        registry.iter().map(|m| m.logicalname.clone()).collect()
    };

    // Tables with no live rows.
    let empty: Vec<String> = sqlx::query_scalar(
        "SELECT relname::text FROM pg_stat_user_tables \
         WHERE relname = ANY($1) AND n_live_tup = 0 ORDER BY relname",
    )
    .bind(&names)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    findings.extend(empty.into_iter().map(|entity| Finding {
        kind: "unused_entity".into(),
        entity,
        attribute: None,
        detail: "the entity has no records".into(),
    }));

    // Columns every analysed row leaves empty.
    let always_null: Vec<(String, String)> = sqlx::query_as(
        "SELECT tablename::text, attname::text FROM pg_stats \
         WHERE tablename = ANY($1) AND null_frac >= 1 ORDER BY tablename, attname",
    )
    .bind(&names)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    findings.extend(
        always_null
            .into_iter()
            .filter(|(_, column)| !attome_core::ALL_SYSTEM_COLS.contains(&column.as_str()))
            .map(|(entity, column)| Finding {
                kind: "unused_attribute".into(),
                entity,
                attribute: Some(column),
                detail: "no analysed record has a value".into(),
            }),
    );

    // Filterable attributes no index starts with.
    let indexed: Vec<(String, String)> = sqlx::query_as(
        "SELECT t.relname::text, a.attname::text \
         FROM pg_index i \
         JOIN pg_class t ON t.oid = i.indrelid \
         JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = i.indkey[0] \
         WHERE t.relname = ANY($1)",
    )
    .bind(&names)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let indexed: HashSet<(String, String)> = indexed.into_iter().collect();
    findings.extend(
        filterable
            .into_iter()
            .filter(|key| !indexed.contains(key))
            .map(|(entity, attribute)| Finding {
                kind: "index_proposal".into(),
                entity,
                attribute: Some(attribute),
                detail: "filterable, but no index starts with it".into(),
            }),
    );

    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    findings.retain(|f| {
        let n = counts.entry(f.kind.clone()).or_default();
        *n += 1;
        *n <= MAX_FINDINGS
    });
    Ok(Json(ModelHealth { entities, findings }))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/admin/model/health", get(model_health))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(model_health), components(schemas(ModelHealth, Finding)))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn names_that_mean_the_same_collapse() {
        assert_eq!(name_key("phone_no"), name_key("phone_number"));
        assert_eq!(name_key("Mobile"), name_key("phone"));
        assert_eq!(name_key("email_address"), name_key("Email"));
        assert_ne!(name_key("first_name"), name_key("last_name"));
    }

    #[test]
    fn broken_lookups_and_duplicates_are_found() {
        let target = uuid::Uuid::now_v7();
        let meta: EntityMeta = serde_json::from_value(json!({
            "entity_id": uuid::Uuid::now_v7(),
            "logicalname": "deal",
            "is_append_only": false,
            "attrs": [
                { "logicalname": "account_ref", "field_type_int": 11, "is_sensitive": false,
                  "is_sortable": false, "is_filterable": false, "lookup_entity_ref": target },
                { "logicalname": "owner_ref", "field_type_int": 11, "is_sensitive": false,
                  "is_sortable": false, "is_filterable": false, "lookup_entity_ref": null },
                { "logicalname": "phone_no", "field_type_int": 3, "is_sensitive": false,
                  "is_sortable": false, "is_filterable": false },
                { "logicalname": "phone_number", "field_type_int": 3, "is_sensitive": false,
                  "is_sortable": false, "is_filterable": false }
            ]
        }))
        .unwrap();
        let known: HashSet<uuid::Uuid> = [target].into_iter().collect();
        let findings = registry_findings(&meta, &known);
        let kinds: Vec<(&str, Option<&str>)> = findings
            .iter()
            .map(|f| (f.kind.as_str(), f.attribute.as_deref()))
            .collect();
        assert_eq!(
            kinds,
            [
                ("broken_reference", Some("owner_ref")),
                ("duplicate_attribute", Some("phone_no, phone_number")),
            ]
        );
    }
}
