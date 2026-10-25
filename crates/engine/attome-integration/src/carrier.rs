//! F6-T9: the carrier seam. A carrier is an `integration_system` row whose
//! `config` names `"carrier": "aramex"` with the account fields its adapter
//! reads and a `shipper` block (the ship-from party: `name`, `company`,
//! `phone`, `email`, `line1`, `city`, `country_code`); the account password
//! is the system's envelope-encrypted credential. `base_url` replaces the
//! carrier's production endpoint (its test environment, or a local fake).
//!
//! [`book`] books one shipment and answers its tracking number and label
//! URL; [`track`] reads a waybill's latest update. Both answer `Ok(None)`
//! when no such carrier is configured, so a deployment without one keeps
//! booking by hand. A carrier refusal (an address it cannot deliver to) is
//! a 422 naming the carrier's reason.

use std::sync::OnceLock;
use std::time::Duration;

use attome_core::EngineState;
use attome_types::AppError;
use serde_json::Value;

use crate::connector::adapters::carrier_aramex::{
    self as aramex, BookAnswer, Parcel, Party, TrackingUpdate,
};
use crate::connector::adapters::carrier_smsa as smsa;

const CALL_TIMEOUT: Duration = Duration::from_secs(30);

fn client() -> &'static attome_outbound::http::Outbound {
    // Q21-T1: the carrier's public API only.
    static CLIENT: OnceLock<attome_outbound::http::Outbound> = OnceLock::new();
    CLIENT.get_or_init(|| {
        attome_outbound::http::shared(attome_outbound::http::Purpose::public("carrier"), |b| {
            b.timeout(CALL_TIMEOUT)
        })
    })
}

struct CarrierSystem {
    config: Value,
    secret: String,
}

async fn system(state: &EngineState, carrier: &str) -> Result<Option<CarrierSystem>, AppError> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT config, credential_ref FROM integration_system \
          WHERE status = 'active' AND (is_active IS NULL OR is_active = true) \
            AND CASE WHEN config IS JSON OBJECT THEN config::jsonb ->> 'carrier' END = $1 \
          ORDER BY created_at, id LIMIT 1",
    )
    .bind(carrier)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((config, credential_ref)) = row else {
        return Ok(None);
    };
    let config: Value = config
        .and_then(|c| serde_json::from_str(&c).ok())
        .unwrap_or(Value::Null);
    let Some(secret) = crate::credential::resolve_value(
        &state.base.db,
        &crate::credential::ring(state),
        credential_ref.as_deref(),
    )
    .await?
    else {
        tracing::warn!(%carrier, "carrier: configured without a credential");
        return Ok(None);
    };
    Ok(Some(CarrierSystem { config, secret }))
}

/// The carriers an adapter books and tracks with.
pub const CARRIERS: [&str; 2] = ["aramex", "smsa"];

fn base_url(carrier: &str, config: &Value) -> String {
    config
        .get("base_url")
        .and_then(Value::as_str)
        .filter(|u| !u.trim().is_empty())
        .unwrap_or(if carrier == "smsa" {
            smsa::DEFAULT_BASE
        } else {
            aramex::DEFAULT_BASE
        })
        .to_owned()
}

/// The ship-from party in a carrier system's `shipper` block.
pub fn shipper_of(config: &Value) -> Party {
    let s = config.get("shipper").unwrap_or(&Value::Null);
    let text = |key: &str| {
        s.get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    Party {
        name: text("name"),
        company: text("company"),
        phone: text("phone"),
        email: text("email"),
        line1: text("line1"),
        city: text("city"),
        country_code: text("country_code"),
    }
}

/// A booked shipment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Booking {
    pub tracking_number: String,
    pub label_url: Option<String>,
}

async fn send(request: reqwest::RequestBuilder) -> Result<(u16, String), AppError> {
    let res = request.send().await.map_err(AppError::internal)?;
    let status = res.status().as_u16();
    Ok((status, res.text().await.unwrap_or_default()))
}

async fn post_json(url: String, body: &Value) -> Result<(u16, String), AppError> {
    send(client().post(url).json(body)).await
}

fn unsupported(carrier: &str) -> AppError {
    AppError::Validation(format!("no adapter books shipments with `{carrier}`"))
}

/// Books one shipment with `carrier` to `consignee`. `Ok(None)` when the
/// carrier is not configured.
pub async fn book(
    state: &EngineState,
    carrier: &str,
    consignee: &Party,
    parcel: &Parcel,
) -> Result<Option<Booking>, AppError> {
    if !CARRIERS.contains(&carrier) {
        return Err(unsupported(carrier));
    }
    let Some(system) = system(state, carrier).await? else {
        return Ok(None);
    };
    let base = base_url(carrier, &system.config);
    let shipper = shipper_of(&system.config);
    let (status, text) = if carrier == "smsa" {
        let body = smsa::create_body(
            &shipper,
            consignee,
            parcel,
            // SMSA reads the ship date in Saudi local time.
            &(chrono::Utc::now() + chrono::Duration::hours(3))
                .format("%Y-%m-%dT%H:%M:%S")
                .to_string(),
            system
                .config
                .get("currency")
                .and_then(Value::as_str)
                .unwrap_or("SAR"),
        );
        send(
            client()
                .post(smsa::create_url(&base))
                .header(smsa::API_KEY_HEADER, &system.secret)
                .json(&body),
        )
        .await?
    } else {
        let info = aramex::client_info(&system.config, &system.secret);
        let body = aramex::create_body(
            &info,
            &shipper,
            consignee,
            parcel,
            chrono::Utc::now().timestamp_millis(),
        );
        post_json(aramex::create_url(&base), &body).await?
    };
    let answer = if carrier == "smsa" {
        smsa::parse_create(status, &text)
    } else {
        aramex::parse_create(status, &text)
    };
    match answer {
        BookAnswer::Booked {
            tracking_number,
            label_url,
        } => Ok(Some(Booking {
            tracking_number,
            label_url,
        })),
        BookAnswer::Refused { message } => Err(AppError::Validation(format!(
            "{carrier} refused the booking: {message}"
        ))),
    }
}

/// The latest update of `tracking_number` with `carrier`. `Ok(None)` when
/// the carrier is not configured or has nothing for the waybill.
pub async fn track(
    state: &EngineState,
    carrier: &str,
    tracking_number: &str,
) -> Result<Option<TrackingUpdate>, AppError> {
    if !CARRIERS.contains(&carrier) {
        return Err(unsupported(carrier));
    }
    let Some(system) = system(state, carrier).await? else {
        return Ok(None);
    };
    let base = base_url(carrier, &system.config);
    if carrier == "smsa" {
        let (status, text) = send(
            client()
                .get(smsa::track_url(&base, tracking_number))
                .header(smsa::API_KEY_HEADER, &system.secret),
        )
        .await?;
        return Ok(smsa::parse_track(status, &text, tracking_number));
    }
    let info = aramex::client_info(&system.config, &system.secret);
    let body = aramex::track_body(&info, &[tracking_number.to_owned()]);
    let (status, text) = post_json(aramex::track_url(&base), &body).await?;
    Ok(aramex::parse_track(status, &text, tracking_number))
}

/// F6-T10: the latest updates of many waybills with `carrier`, in one call
/// per [`TRACK_BATCH`] waybills. `Ok(None)` when the carrier is not
/// configured; waybills the carrier has nothing for are left out.
pub async fn track_many(
    state: &EngineState,
    carrier: &str,
    tracking_numbers: &[String],
) -> Result<Option<Vec<(String, TrackingUpdate)>>, AppError> {
    if !CARRIERS.contains(&carrier) {
        return Err(unsupported(carrier));
    }
    let Some(system) = system(state, carrier).await? else {
        return Ok(None);
    };
    let base = base_url(carrier, &system.config);
    let mut out = Vec::new();
    for chunk in tracking_numbers.chunks(TRACK_BATCH) {
        if carrier == "smsa" {
            let (status, text) = send(
                client()
                    .post(smsa::track_bulk_url(&base))
                    .header(smsa::API_KEY_HEADER, &system.secret)
                    .json(&smsa::track_bulk_body(chunk)),
            )
            .await?;
            out.extend(smsa::parse_track_bulk(status, &text));
        } else {
            let info = aramex::client_info(&system.config, &system.secret);
            let body = aramex::track_body(&info, chunk);
            let (status, text) = post_json(aramex::track_url(&base), &body).await?;
            out.extend(
                chunk
                    .iter()
                    .filter_map(|n| aramex::parse_track(status, &text, n).map(|u| (n.clone(), u))),
            );
        }
    }
    Ok(Some(out))
}

/// Most waybills one tracking call asks for.
pub const TRACK_BATCH: usize = 200;

/// F6-T10: the integration-event type a carrier system's pushed tracking
/// event lands as (the REST adapter's webhook, for a system whose config
/// names a `carrier`).
pub const PUSH_EVENT: &str = "carrier.tracking";

/// F6-T10: the updates in one pushed tracking event, each waybill's
/// latest. SMSA pushes its tracking objects (one, or an array); Aramex its
/// `TrackingResults`. Pure.
pub fn decode_push(carrier: &str, payload: &Value) -> Vec<(String, TrackingUpdate)> {
    match carrier {
        "smsa" => match payload {
            Value::Array(items) => items.iter().filter_map(smsa::update_of).collect(),
            one => smsa::update_of(one).into_iter().collect(),
        },
        "aramex" => {
            let text = payload.to_string();
            payload["TrackingResults"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|r| r["Key"].as_str())
                .filter_map(|key| aramex::parse_track(200, &text, key).map(|u| (key.to_owned(), u)))
                .collect()
        }
        _ => Vec::new(),
    }
}

/// F6-T10: whether `carrier`'s system says the carrier pushes its tracking
/// events (`"push_events": true` in its config), so polling skips it.
pub async fn pushes_events(state: &EngineState, carrier: &str) -> Result<bool, AppError> {
    Ok(system_config(state, carrier)
        .await?
        .is_some_and(|c| c.get("push_events").and_then(Value::as_bool) == Some(true)))
}

async fn system_config(state: &EngineState, carrier: &str) -> Result<Option<Value>, AppError> {
    let config: Option<Option<String>> = sqlx::query_scalar(
        "SELECT config FROM integration_system \
          WHERE status = 'active' AND (is_active IS NULL OR is_active = true) \
            AND CASE WHEN config IS JSON OBJECT THEN config::jsonb ->> 'carrier' END = $1 \
          ORDER BY created_at, id LIMIT 1",
    )
    .bind(carrier)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(config.flatten().and_then(|c| serde_json::from_str(&c).ok()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn shipper_and_base_url_come_from_the_system_config() {
        let config = json!({
            "carrier": "aramex",
            "base_url": "https://ws.dev.aramex.net/ShippingAPI.V2",
            "shipper": { "name": "Store", "city": "Jeddah", "country_code": "SA" }
        });
        let shipper = shipper_of(&config);
        assert_eq!(shipper.city, "Jeddah");
        assert_eq!(shipper.phone, "");
        assert_eq!(
            base_url("aramex", &config),
            "https://ws.dev.aramex.net/ShippingAPI.V2"
        );
        assert_eq!(base_url("aramex", &json!({})), aramex::DEFAULT_BASE);
        assert_eq!(base_url("smsa", &json!({})), smsa::DEFAULT_BASE);
    }

    #[test]
    fn pushed_events_decode_per_carrier() {
        let smsa = json!({"AWB": "231", "isDelivered": true, "Scans": [
            {"ScanType": "DL", "ScanDescription": "Delivered", "ScanDateTime": "2026-10-25T11:30:00", "ScanTimeZone": "+03:00"}]});
        let updates = decode_push("smsa", &smsa);
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].0, "231");
        assert_eq!(updates[0].1.status, "delivered");
        assert_eq!(decode_push("smsa", &json!([smsa])).len(), 1);
        let aramex = json!({"TrackingResults": [{"Key": "44221", "Value": [
            {"UpdateCode": "SH003", "UpdateDescription": "Out for delivery", "UpdateDateTime": "/Date(1700000000000)/"}]}]});
        let updates = decode_push("aramex", &aramex);
        assert_eq!(updates[0].0, "44221");
        assert_eq!(updates[0].1.status, "out_for_delivery");
        assert!(decode_push("dhl", &aramex).is_empty());
    }
}
