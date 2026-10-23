//! S14-T1: a connector operation as a flow step.
//!
//! A flow's `connector` node names an integration system (its `name`) whose
//! `config.sdk` is a connector [`Definition`], and one of the definition's
//! endpoints (the operation). [`run`] calls it: a `GET` endpoint reads every
//! record, page after page (`{"count": n, "records": [...]}`); any other
//! method sends the node's body once (`{"response": ...}`), with the flow's
//! effect key as the call's `Idempotency-Key`. The node's parameters fill
//! the endpoint's path template.
//!
//! [`run_named`] loads the system and its credential and calls it over the
//! SSRF-guarded client; [`run`] takes any [`Transport`], so a test drives a
//! whole flow between two mock systems.

use std::collections::BTreeMap;

use attome_core::EngineState;
use attome_types::AppError;
use serde_json::{Value, json};

use super::sdk::{Definition, GuardedTransport, Runtime, Secret, Transport};

/// How long one call may take.
const TIMEOUT_SECS: u64 = 30;

/// A node's parameters (an object of text, numbers and true/false) as the
/// runtime's path parameters.
pub fn params_of(value: &Value) -> Result<BTreeMap<String, String>, AppError> {
    match value {
        Value::Null => Ok(BTreeMap::new()),
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| {
                let text = match v {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    _ => {
                        return Err(AppError::Validation(format!(
                            "connector parameter {k} is text, a number or true/false"
                        )));
                    }
                };
                Ok((k.clone(), text))
            })
            .collect(),
        _ => Err(AppError::Validation(
            "connector parameters are an object".into(),
        )),
    }
}

/// Runs `operation` of `definition` over `transport`.
pub async fn run(
    definition: &Definition,
    transport: &dyn Transport,
    secret: Option<Secret>,
    operation: &str,
    params: &Value,
    body: Option<&Value>,
    idempotency_key: Option<&str>,
) -> Result<Value, AppError> {
    let endpoint = definition.endpoints.get(operation).ok_or_else(|| {
        AppError::Validation(format!("{} has no operation {operation}", definition.name))
    })?;
    let params = params_of(params)?;
    let mut runtime = Runtime::new(definition, transport, secret);
    if endpoint.method == "GET" {
        let records = runtime.fetch_all(operation, &params).await?;
        Ok(json!({ "count": records.len(), "records": records }))
    } else {
        let response = runtime
            .call(operation, &params, body, idempotency_key)
            .await?;
        Ok(json!({ "response": response }))
    }
}

/// The active integration system named `system`: its connector definition
/// and credential.
pub async fn definition_of(
    state: &EngineState,
    system: &str,
) -> Result<(Definition, Option<Secret>), AppError> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT config, credential_ref FROM integration_system \
          WHERE name = $1 AND status = 'active' AND (is_active IS NULL OR is_active = true)",
    )
    .bind(system)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((config, credential_ref)) = row else {
        return Err(AppError::Validation(format!(
            "no active integration system {system}"
        )));
    };
    let config: Value = config
        .and_then(|c| serde_json::from_str(&c).ok())
        .unwrap_or(Value::Null);
    let definition = Definition::from_config(&config)
        .map_err(|problems| AppError::Validation(format!("{system}: {}", problems.join("; "))))?;
    let secret = crate::credential::resolve_value(
        &state.base.db,
        &crate::credential::ring(state),
        credential_ref.as_deref(),
    )
    .await?
    .map(Secret::new);
    Ok((definition, secret))
}

/// Runs `operation` of the integration system named `system`.
pub async fn run_named(
    state: &EngineState,
    system: &str,
    operation: &str,
    params: &Value,
    body: Option<&Value>,
    idempotency_key: Option<&str>,
) -> Result<Value, AppError> {
    let (definition, secret) = definition_of(state, system).await?;
    let client =
        attome_server::ssrf_guard::GuardedClient::new(TIMEOUT_SECS).map_err(AppError::internal)?;
    run(
        &definition,
        &GuardedTransport(client),
        secret,
        operation,
        params,
        body,
        idempotency_key,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connector_flow_params_are_flat_values() {
        let p = params_of(&json!({"id": 7, "name": "a b", "vip": true})).unwrap();
        assert_eq!(p["id"], "7");
        assert_eq!(p["vip"], "true");
        assert!(params_of(&json!({"x": [1]})).is_err());
        assert!(params_of(&json!([1])).is_err());
        assert!(params_of(&Value::Null).unwrap().is_empty());
    }
}
