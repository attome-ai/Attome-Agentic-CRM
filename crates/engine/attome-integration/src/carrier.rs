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

fn base_url(config: &Value) -> String {
    config
        .get("base_url")
        .and_then(Value::as_str)
        .filter(|u| !u.trim().is_empty())
        .unwrap_or(aramex::DEFAULT_BASE)
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

async fn post_json(url: String, body: &Value) -> Result<(u16, String), AppError> {
    let res = client()
        .post(url)
        .json(body)
        .send()
        .await
        .map_err(AppError::internal)?;
    let status = res.status().as_u16();
    Ok((status, res.text().await.unwrap_or_default()))
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
    if carrier != "aramex" {
        return Err(unsupported(carrier));
    }
    let Some(system) = system(state, carrier).await? else {
        return Ok(None);
    };
    let info = aramex::client_info(&system.config, &system.secret);
    let body = aramex::create_body(
        &info,
        &shipper_of(&system.config),
        consignee,
        parcel,
        chrono::Utc::now().timestamp_millis(),
    );
    let (status, text) = post_json(aramex::create_url(&base_url(&system.config)), &body).await?;
    match aramex::parse_create(status, &text) {
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
    if carrier != "aramex" {
        return Err(unsupported(carrier));
    }
    let Some(system) = system(state, carrier).await? else {
        return Ok(None);
    };
    let info = aramex::client_info(&system.config, &system.secret);
    let body = aramex::track_body(&info, tracking_number);
    let (status, text) = post_json(aramex::track_url(&base_url(&system.config)), &body).await?;
    Ok(aramex::parse_track(status, &text, tracking_number))
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
            base_url(&config),
            "https://ws.dev.aramex.net/ShippingAPI.V2"
        );
        assert_eq!(base_url(&json!({})), aramex::DEFAULT_BASE);
    }
}
