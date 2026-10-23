//! S14-T1: the `map` node's transform — a JSON value into the shape
//! another system wants, by a mapping definition.
//!
//! `config.mapping` is an object of target field to source: a JSON pointer
//! into the input (`"/customer/name"`, `""` for the whole input),
//! `{"from": pointer, "default": value}`, or `{"value": value}` for a
//! constant. A dotted target (`"address.city"`) builds nested objects.
//! `config.each`, a pointer to a list in the input (`"/records"`), maps
//! every element instead and gives a list. A source the input lacks maps to
//! `null`, or to its default. Pure: no lookup and no I/O, so a dry run maps
//! for real.

use serde_json::{Map, Value};

/// The most target fields one mapping has.
pub const MAX_FIELDS: usize = 500;
/// The most list elements one map node maps.
pub const MAX_ITEMS: usize = 100_000;

enum Source<'a> {
    Pointer(&'a str, Option<&'a Value>),
    Constant(&'a Value),
}

fn pointer(p: &str) -> Result<&str, String> {
    if p.is_empty() || p.starts_with('/') {
        Ok(p)
    } else {
        Err(format!("{p:?} is not a JSON pointer (it starts with /)"))
    }
}

fn source(v: &Value) -> Result<Source<'_>, String> {
    match v {
        Value::String(p) => Ok(Source::Pointer(pointer(p)?, None)),
        Value::Object(o) if o.contains_key("value") && o.len() == 1 => {
            Ok(Source::Constant(&o["value"]))
        }
        Value::Object(o) => match o.get("from").and_then(Value::as_str) {
            Some(p) if o.keys().all(|k| k == "from" || k == "default") => {
                Ok(Source::Pointer(pointer(p)?, o.get("default")))
            }
            _ => Err("a source is a pointer, {\"from\", \"default\"} or {\"value\"}".into()),
        },
        _ => Err("a source is a pointer, {\"from\", \"default\"} or {\"value\"}".into()),
    }
}

/// Every problem with a map node's `mapping` and `each`.
pub fn check(mapping: Option<&Value>, each: Option<&Value>) -> Result<(), String> {
    let mapping = mapping
        .and_then(Value::as_object)
        .ok_or("config.mapping is an object of target field to source")?;
    if mapping.is_empty() || mapping.len() > MAX_FIELDS {
        return Err(format!(
            "config.mapping has 1 to {MAX_FIELDS} target fields"
        ));
    }
    for (target, src) in mapping {
        if target.split('.').any(str::is_empty) {
            return Err(format!("target {target:?} has an empty part"));
        }
        source(src).map_err(|e| format!("{target}: {e}"))?;
    }
    match each {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(p)) => pointer(p).map(|_| ()),
        Some(_) => Err("config.each is a JSON pointer to a list".into()),
    }
}

/// Maps `input` by `mapping`, every element of the list at `each` when
/// given.
pub fn apply(mapping: &Value, each: Option<&str>, input: &Value) -> Result<Value, String> {
    check(
        Some(mapping),
        each.map(|e| Value::String(e.to_owned())).as_ref(),
    )?;
    let Some(fields) = mapping.as_object() else {
        return Err("config.mapping is an object".into());
    };
    let Some(each) = each else {
        return Ok(one(fields, input));
    };
    let items = input
        .pointer(each)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{each} is not a list in the input"))?;
    if items.len() > MAX_ITEMS {
        return Err(format!("{each} has more than {MAX_ITEMS} elements"));
    }
    Ok(Value::Array(
        items.iter().map(|item| one(fields, item)).collect(),
    ))
}

fn one(fields: &Map<String, Value>, item: &Value) -> Value {
    let mut out = Map::new();
    for (target, src) in fields {
        let value = match source(src) {
            Ok(Source::Constant(v)) => v.clone(),
            Ok(Source::Pointer(p, default)) => item
                .pointer(p)
                .filter(|v| !v.is_null())
                .or(default)
                .cloned()
                .unwrap_or(Value::Null),
            // `check` refused it already.
            Err(_) => Value::Null,
        };
        set(&mut out, target, value);
    }
    Value::Object(out)
}

fn set(out: &mut Map<String, Value>, target: &str, value: Value) {
    let mut parts: Vec<&str> = target.split('.').collect();
    let Some(last) = parts.pop() else {
        return;
    };
    let mut at = out;
    for part in parts {
        let slot = at
            .entry(part.to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        if !slot.is_object() {
            *slot = Value::Object(Map::new());
        }
        let Some(next) = slot.as_object_mut() else {
            return;
        };
        at = next;
    }
    at.insert(last.to_owned(), value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_integration::connector::{flow, sdk};
    use serde_json::json;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    #[test]
    fn connector_nodes_map_reshapes_one_value() {
        let mapping = json!({
            "name": "/customer/full_name",
            "address.city": "/customer/city",
            "address.country": { "value": "SA" },
            "tier": { "from": "/customer/tier", "default": "standard" }
        });
        let out = apply(
            &mapping,
            None,
            &json!({ "customer": { "full_name": "Sara", "city": "Riyadh" } }),
        )
        .unwrap();
        assert_eq!(
            out,
            json!({
                "name": "Sara",
                "address": { "city": "Riyadh", "country": "SA" },
                "tier": "standard"
            })
        );
    }

    #[test]
    fn connector_nodes_map_each_maps_a_list_and_refuses_bad_definitions() {
        let out = apply(
            &json!({ "id": "/code" }),
            Some("/records"),
            &json!({ "records": [{ "code": 1 }, { "code": 2 }] }),
        )
        .unwrap();
        assert_eq!(out, json!([{ "id": 1 }, { "id": 2 }]));
        assert!(apply(&json!({ "id": "/code" }), Some("/none"), &json!({})).is_err());
        for bad in [
            json!({}),
            json!({ "id": "code" }),
            json!({ "id": 3 }),
            json!({ "a..b": "/x" }),
            json!({ "id": { "from": "/x", "other": 1 } }),
        ] {
            assert!(check(Some(&bad), None).is_err(), "{bad}");
        }
        assert!(check(None, None).is_err());
        assert!(check(Some(&json!({ "id": "/x" })), Some(&json!(3))).is_err());
    }

    /// One mock outside system: answers in order, recording each request.
    struct System {
        answers: Mutex<Vec<sdk::Response>>,
        seen: Mutex<Vec<sdk::Request>>,
    }

    impl System {
        fn answering(bodies: &[&str]) -> Self {
            System {
                answers: Mutex::new(
                    bodies
                        .iter()
                        .rev()
                        .map(|b| sdk::Response {
                            status: 200,
                            headers: vec![],
                            body: (*b).to_owned(),
                        })
                        .collect(),
                ),
                seen: Mutex::new(vec![]),
            }
        }
    }

    impl sdk::Transport for System {
        fn send<'a>(
            &'a self,
            request: sdk::Request,
        ) -> Pin<Box<dyn Future<Output = Result<sdk::Response, attome_types::AppError>> + Send + 'a>>
        {
            self.seen.lock().unwrap().push(request);
            let answer = self.answers.lock().unwrap().pop();
            Box::pin(async move {
                answer.ok_or_else(|| attome_types::AppError::internal("no more answers"))
            })
        }
    }

    fn definition(value: Value) -> sdk::Definition {
        sdk::Definition::from_config(&json!({ "sdk": value })).unwrap()
    }

    /// The task's done-when: a flow moves data between two outside systems
    /// — a connector node reads the shop's customers, a map node reshapes
    /// them, and a connector node creates each in the ERP.
    #[tokio::test]
    async fn connector_nodes_move_data_between_two_outside_systems() {
        let shop = definition(json!({
            "name": "shop",
            "base_url": "https://shop.example",
            "auth": { "kind": "bearer" },
            "endpoints": { "customers": { "path": "/customers", "records": "/data" } }
        }));
        let erp = definition(json!({
            "name": "erp",
            "base_url": "https://erp.example/api",
            "auth": { "kind": "header", "header": "X-Api-Key" },
            "endpoints": { "create_partner": { "method": "POST", "path": "/partners" } }
        }));
        let shop_api = System::answering(&[
            r#"{"data":[{"id":1,"first":"Sara","email":"s@x.sa"},{"id":2,"first":"Omar","email":null}]}"#,
        ]);
        let erp_api = System::answering(&[r#"{"partner_id":10}"#, r#"{"partner_id":11}"#]);

        let read = flow::run(
            &shop,
            &shop_api,
            Some(sdk::Secret::new("shop-token")),
            "customers",
            &Value::Null,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(read["count"], 2);
        let partners = apply(
            &json!({
                "name": "/first",
                "email": { "from": "/email", "default": "none@shop.example" },
                "ref": "/id",
                "source": { "value": "shop" }
            }),
            Some("/records"),
            &read,
        )
        .unwrap();
        for (i, partner) in partners.as_array().unwrap().iter().enumerate() {
            let key = format!("run:write:{i}");
            let wrote = flow::run(
                &erp,
                &erp_api,
                Some(sdk::Secret::new("erp-key")),
                "create_partner",
                &Value::Null,
                Some(partner),
                Some(&key),
            )
            .await
            .unwrap();
            assert_eq!(wrote["response"]["partner_id"], 10 + i);
        }

        let sent = erp_api.seen.lock().unwrap();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].url, "https://erp.example/api/partners");
        let first: Value = serde_json::from_str(sent[0].body.as_deref().unwrap()).unwrap();
        assert_eq!(
            first,
            json!({ "name": "Sara", "email": "s@x.sa", "ref": 1, "source": "shop" })
        );
        let second: Value = serde_json::from_str(sent[1].body.as_deref().unwrap()).unwrap();
        assert_eq!(second["email"], "none@shop.example");
        assert!(
            sent[1]
                .headers
                .contains(&("X-Api-Key".into(), "erp-key".into()))
        );
        assert!(
            sent[1]
                .headers
                .contains(&("Idempotency-Key".into(), "run:write:1".into()))
        );
        let read_from = shop_api.seen.lock().unwrap();
        assert_eq!(read_from[0].url, "https://shop.example/customers");
    }
}
