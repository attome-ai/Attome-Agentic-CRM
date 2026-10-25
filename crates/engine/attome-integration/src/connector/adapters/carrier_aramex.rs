//! F6-T9: Aramex shipping, as pure request and answer codecs (the carrier
//! seam in [`crate::carrier`] does the HTTP).
//!
//! Booking: `POST {base}/Shipping/Service_1_0.svc/json/CreateShipments` with
//! the account's `ClientInfo`, one shipment (shipper, consignee, weight,
//! pieces, product group and type) and a label request answered as a URL.
//! The answer carries `HasErrors`, `Notifications` and, per shipment, its
//! `ID` (the air waybill, our tracking number) and `ShipmentLabel.LabelURL`.
//!
//! Tracking: `POST {base}/Tracking/Service_1_0.svc/json/TrackShipments` for
//! one waybill with `GetLastTrackingUpdateOnly`. Each update has an
//! `UpdateCode` (`SH…`), a description and a `/Date(ms)/` time; the code
//! maps onto the shipment's status.

use serde_json::{Value, json};

/// Aramex's production endpoint; `base_url` in the system's config replaces
/// it (the test environment, or a local fake).
pub const DEFAULT_BASE: &str = "https://ws.aramex.net/ShippingAPI.V2";

/// The booking URL under `base`.
pub fn create_url(base: &str) -> String {
    format!(
        "{}/Shipping/Service_1_0.svc/json/CreateShipments",
        base.trim_end_matches('/')
    )
}

/// The tracking URL under `base`.
pub fn track_url(base: &str) -> String {
    format!(
        "{}/Tracking/Service_1_0.svc/json/TrackShipments",
        base.trim_end_matches('/')
    )
}

/// One end of a shipment.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Party {
    pub name: String,
    pub company: String,
    pub phone: String,
    pub email: String,
    pub line1: String,
    pub city: String,
    /// ISO 3166-1 alpha-2.
    pub country_code: String,
}

/// What is booked.
#[derive(Debug, Clone, PartialEq)]
pub struct Parcel {
    /// Our reference (the shipment record's id), echoed back by Aramex.
    pub reference: String,
    pub weight_kg: f64,
    pub pieces: u32,
    pub description: String,
}

fn text(cfg: &Value, key: &str) -> String {
    cfg.get(key)
        .map(|v| match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .unwrap_or_default()
}

/// The account block every call carries. `cfg` is the system's config
/// (`username`, `account_number`, `account_pin`, `account_entity`,
/// `account_country_code`); `password` is its encrypted credential.
pub fn client_info(cfg: &Value, password: &str) -> Value {
    json!({
        "UserName": text(cfg, "username"),
        "Password": password,
        "Version": "v1.0",
        "AccountNumber": text(cfg, "account_number"),
        "AccountPin": text(cfg, "account_pin"),
        "AccountEntity": text(cfg, "account_entity"),
        "AccountCountryCode": text(cfg, "account_country_code"),
        "Source": 24,
    })
}

fn party(p: &Party) -> Value {
    let company = if p.company.is_empty() {
        &p.name
    } else {
        &p.company
    };
    json!({
        "PartyAddress": {
            "Line1": p.line1,
            "City": p.city,
            "CountryCode": p.country_code,
        },
        "Contact": {
            "PersonName": p.name,
            "CompanyName": company,
            "PhoneNumber1": p.phone,
            "CellPhone": p.phone,
            "EmailAddress": p.email,
        },
    })
}

/// The booking request. A shipment inside one country is `DOM` with the
/// on-network product, across borders `EXP` with priority parcel express.
/// `shipped_at_ms` is the pickup time in Unix milliseconds. Pure.
pub fn create_body(
    info: &Value,
    shipper: &Party,
    consignee: &Party,
    parcel: &Parcel,
    shipped_at_ms: i64,
) -> Value {
    let domestic = shipper
        .country_code
        .eq_ignore_ascii_case(&consignee.country_code);
    let (group, product) = if domestic {
        ("DOM", "ONP")
    } else {
        ("EXP", "PPX")
    };
    json!({
        "ClientInfo": info,
        "LabelInfo": { "ReportID": 9729, "ReportType": "URL" },
        "Shipments": [{
            "Reference1": parcel.reference,
            "Shipper": party(shipper),
            "Consignee": party(consignee),
            "ShippingDateTime": format!("/Date({shipped_at_ms})/"),
            "Details": {
                "ActualWeight": { "Unit": "KG", "Value": parcel.weight_kg },
                "NumberOfPieces": parcel.pieces,
                "ProductGroup": group,
                "ProductType": product,
                "PaymentType": "P",
                "DescriptionOfGoods": parcel.description,
                "GoodsOriginCountry": shipper.country_code,
            },
        }],
        "Transaction": { "Reference1": parcel.reference },
    })
}

/// What a booking answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BookAnswer {
    Booked {
        tracking_number: String,
        label_url: Option<String>,
    },
    Refused {
        message: String,
    },
}

fn notifications(v: Option<&Value>) -> String {
    v.and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|n| {
                    format!(
                        "{} {}",
                        n["Code"].as_str().unwrap_or_default(),
                        n["Message"].as_str().unwrap_or_default()
                    )
                    .trim()
                    .to_owned()
                })
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join("; ")
        })
        .unwrap_or_default()
}

/// Reads a booking answer. Pure.
pub fn parse_create(status: u16, body: &str) -> BookAnswer {
    let json: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let shipment = json.pointer("/Shipments/0");
    let failed = !(200..300).contains(&status)
        || json["HasErrors"].as_bool() != Some(false)
        || shipment.is_none_or(|s| s["HasErrors"].as_bool() == Some(true));
    let tracking = shipment
        .and_then(|s| s["ID"].as_str())
        .map(str::trim)
        .filter(|id| !id.is_empty());
    match (failed, tracking) {
        (false, Some(id)) => BookAnswer::Booked {
            tracking_number: id.to_owned(),
            label_url: shipment
                .and_then(|s| s.pointer("/ShipmentLabel/LabelURL"))
                .and_then(Value::as_str)
                .filter(|u| !u.is_empty())
                .map(str::to_owned),
        },
        _ => {
            let mut message = notifications(shipment.and_then(|s| s.get("Notifications")));
            if message.is_empty() {
                message = notifications(json.get("Notifications"));
            }
            if message.is_empty() {
                message = format!("HTTP {status}");
            }
            BookAnswer::Refused { message }
        }
    }
}

/// The tracking request for one waybill. Pure.
pub fn track_body(info: &Value, tracking_number: &str) -> Value {
    json!({
        "ClientInfo": info,
        "Shipments": [tracking_number],
        "GetLastTrackingUpdateOnly": true,
    })
}

/// The latest tracking update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackingUpdate {
    /// Aramex's update code, kept as the shipment's last event key.
    pub code: String,
    /// One of the shipment's statuses.
    pub status: &'static str,
    /// When it happened, Unix milliseconds.
    pub at_ms: Option<i64>,
}

/// The shipment status an Aramex update code means. Pure.
pub fn status_of(code: &str, description: &str) -> &'static str {
    let d = description.to_ascii_lowercase();
    match code {
        "SH005" | "SH006" | "SH007" => "delivered",
        "SH003" | "SH154" => "out_for_delivery",
        "SH012" | "SH014" => "picked_up",
        "SH033" | "SH043" => "failed_attempt",
        "SH069" | "SH160" => "returned",
        _ if d.contains("delivered") => "delivered",
        _ if d.contains("out for delivery") => "out_for_delivery",
        _ if d.contains("return") => "returned",
        _ if d.contains("refused") => "refused",
        _ => "in_transit",
    }
}

fn date_ms(value: &str) -> Option<i64> {
    let inner = value.strip_prefix("/Date(")?.strip_suffix(")/")?;
    // `/Date(1700000000000+0300)/`: the zone suffix does not move the instant.
    let digits: String = inner
        .chars()
        .enumerate()
        .take_while(|(i, c)| c.is_ascii_digit() || (*i == 0 && *c == '-'))
        .map(|(_, c)| c)
        .collect();
    digits.parse().ok()
}

/// Reads a tracking answer: the latest update of `tracking_number`, if any.
/// Pure.
pub fn parse_track(status: u16, body: &str, tracking_number: &str) -> Option<TrackingUpdate> {
    if !(200..300).contains(&status) {
        return None;
    }
    let json: Value = serde_json::from_str(body).ok()?;
    let results = json["TrackingResults"].as_array()?;
    let updates = results
        .iter()
        .find(|r| r["Key"].as_str() == Some(tracking_number))?["Value"]
        .as_array()?;
    let latest = updates.iter().max_by_key(|u| {
        u["UpdateDateTime"]
            .as_str()
            .and_then(date_ms)
            .unwrap_or(i64::MIN)
    })?;
    let code = latest["UpdateCode"].as_str().unwrap_or_default().to_owned();
    let description = latest["UpdateDescription"].as_str().unwrap_or_default();
    Some(TrackingUpdate {
        status: status_of(&code, description),
        at_ms: latest["UpdateDateTime"].as_str().and_then(date_ms),
        code,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn party(country: &str) -> Party {
        Party {
            name: "Sara".into(),
            phone: "+966500000000".into(),
            line1: "King Fahd Rd".into(),
            city: "Riyadh".into(),
            country_code: country.into(),
            ..Party::default()
        }
    }

    #[test]
    fn booking_request_picks_domestic_or_express() {
        let info = client_info(&json!({"username": "u", "account_number": 123}), "p");
        assert_eq!(info["AccountNumber"], "123");
        let parcel = Parcel {
            reference: "ship-1".into(),
            weight_kg: 1.5,
            pieces: 2,
            description: "Books".into(),
        };
        let body = create_body(
            &info,
            &party("SA"),
            &party("SA"),
            &parcel,
            1_700_000_000_000,
        );
        let details = &body["Shipments"][0]["Details"];
        assert_eq!(details["ProductGroup"], "DOM");
        assert_eq!(details["NumberOfPieces"], 2);
        assert_eq!(
            body["Shipments"][0]["ShippingDateTime"],
            "/Date(1700000000000)/"
        );
        let abroad = create_body(&info, &party("SA"), &party("AE"), &parcel, 0);
        assert_eq!(abroad["Shipments"][0]["Details"]["ProductType"], "PPX");
    }

    #[test]
    fn booking_answer_reads_waybill_or_errors() {
        let ok = r#"{"HasErrors":false,"Notifications":[],"Shipments":[{"ID":"44221","HasErrors":false,"ShipmentLabel":{"LabelURL":"https://x/label.pdf"}}]}"#;
        assert_eq!(
            parse_create(200, ok),
            BookAnswer::Booked {
                tracking_number: "44221".into(),
                label_url: Some("https://x/label.pdf".into())
            }
        );
        let refused = r#"{"HasErrors":true,"Shipments":[{"ID":null,"HasErrors":true,"Notifications":[{"Code":"ERR52","Message":"Consignee city is invalid"}]}]}"#;
        assert_eq!(
            parse_create(200, refused),
            BookAnswer::Refused {
                message: "ERR52 Consignee city is invalid".into()
            }
        );
        assert!(matches!(parse_create(500, ""), BookAnswer::Refused { .. }));
    }

    #[test]
    fn tracking_answer_takes_the_latest_update() {
        let body = r#"{"HasErrors":false,"TrackingResults":[{"Key":"44221","Value":[
            {"UpdateCode":"SH012","UpdateDescription":"Picked Up","UpdateDateTime":"/Date(1700000000000+0300)/"},
            {"UpdateCode":"SH005","UpdateDescription":"Delivered","UpdateDateTime":"/Date(1700090000000+0300)/"}]}]}"#;
        assert_eq!(
            parse_track(200, body, "44221"),
            Some(TrackingUpdate {
                code: "SH005".into(),
                status: "delivered",
                at_ms: Some(1_700_090_000_000),
            })
        );
        assert_eq!(parse_track(200, body, "other"), None);
        assert_eq!(
            status_of("SH999", "Shipment refused by consignee"),
            "refused"
        );
    }
}
