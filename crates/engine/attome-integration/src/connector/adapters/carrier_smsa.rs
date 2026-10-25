//! F6-T10: SMSA Express shipping (its eCommerce REST API), as pure request
//! and answer codecs; the carrier seam in [`crate::carrier`] does the HTTP.
//!
//! Every call carries the account's API key in an `apikey` header (the
//! system's encrypted credential). Keys are per environment: a production
//! key is refused by the sandbox host.
//!
//! Booking: `POST {base}/api/shipment/b2c/new` with the consignee and
//! shipper addresses, the order number (our shipment id), the parcel count
//! and weight. The answer carries `sawb` (the shipment's waybill) and
//! `waybills[*].awb` (one per parcel); the first parcel's waybill is our
//! tracking number, as SMSA's tracking reads parcels. SMSA answers labels
//! as a PDF through its query call, not a URL, so a booking has no label
//! URL.
//!
//! Tracking: `GET {base}/api/track/single/{awb}` for one waybill, and
//! `POST {base}/api/track/bulk/` with a bare JSON array of waybills for
//! many. Each answer has the `AWB`, `isDelivered` and `Scans` (newest
//! first), each scan a `ScanType` code (sometimes empty), a
//! `ScanDescription`, and `ScanDateTime` in local time with its
//! `ScanTimeZone` offset.

use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeZone};
use serde_json::{Value, json};

use super::carrier_aramex::{BookAnswer, Parcel, Party, TrackingUpdate};

/// SMSA's production endpoint; `base_url` in the system's config replaces
/// it (the sandbox, `https://ecomapis-sandbox.azurewebsites.net`, or a local
/// fake).
pub const DEFAULT_BASE: &str = "https://ecomapis.smsaexpress.com";

/// The header the API key travels in.
pub const API_KEY_HEADER: &str = "apikey";

/// Most waybills one bulk tracking call asks for.
pub const BULK_MAX: usize = 200;

/// The booking URL under `base`.
pub fn create_url(base: &str) -> String {
    format!("{}/api/shipment/b2c/new", base.trim_end_matches('/'))
}

/// The tracking URL of one waybill under `base`.
pub fn track_url(base: &str, awb: &str) -> String {
    let awb: String = awb
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    format!("{}/api/track/single/{awb}", base.trim_end_matches('/'))
}

/// The bulk tracking URL under `base`.
pub fn track_bulk_url(base: &str) -> String {
    format!("{}/api/track/bulk/", base.trim_end_matches('/'))
}

fn address(p: &Party, consignee: bool) -> Value {
    let name = if p.name.is_empty() {
        &p.company
    } else {
        &p.name
    };
    let mut out = json!({
        "ContactName": name,
        "ContactPhoneNumber": p.phone,
        "Country": p.country_code,
        "City": p.city,
        "AddressLine1": p.line1,
    });
    if consignee && let Some(map) = out.as_object_mut() {
        map.insert("AddressLine2".into(), json!(""));
    }
    out
}

/// The booking request. `ship_date` is the pickup day in local time,
/// `YYYY-MM-DDTHH:MM:SS`; `currency` the declared value's currency. Pure.
pub fn create_body(
    shipper: &Party,
    consignee: &Party,
    parcel: &Parcel,
    ship_date: &str,
    currency: &str,
) -> Value {
    json!({
        "ConsigneeAddress": address(consignee, true),
        "ShipperAddress": address(shipper, false),
        "OrderNumber": parcel.reference,
        "DeclaredValue": 0,
        "CODAmount": 0,
        "Parcels": parcel.pieces.max(1),
        "ShipDate": ship_date,
        "ShipmentCurrency": currency,
        "Weight": parcel.weight_kg,
        "WeightUnit": "KG",
        "ContentDescription": parcel.description,
        "WaybillType": "PDF",
        "VatPaid": true,
        "DutyPaid": false,
    })
}

fn message_of(json: &Value) -> String {
    for key in ["message", "Message", "title", "detail"] {
        if let Some(text) = json.get(key).and_then(Value::as_str)
            && !text.trim().is_empty()
        {
            return text.trim().to_owned();
        }
    }
    // A validation answer: `errors: { field: [messages] }`.
    json.get("errors")
        .and_then(Value::as_object)
        .map(|errors| {
            errors
                .iter()
                .flat_map(|(field, v)| {
                    v.as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(move |m| format!("{field}: {m}"))
                })
                .collect::<Vec<_>>()
                .join("; ")
        })
        .unwrap_or_default()
}

/// Reads a booking answer. Pure.
pub fn parse_create(status: u16, body: &str) -> BookAnswer {
    let json: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let parcel = json
        .pointer("/waybills/0/awb")
        .and_then(Value::as_str)
        .or_else(|| json["sawb"].as_str())
        .map(str::trim)
        .filter(|awb| !awb.is_empty());
    match parcel {
        Some(awb) if (200..300).contains(&status) => BookAnswer::Booked {
            tracking_number: awb.to_owned(),
            label_url: None,
        },
        _ => {
            let mut message = message_of(&json);
            if message.is_empty() {
                message = format!("HTTP {status}");
            }
            BookAnswer::Refused { message }
        }
    }
}

/// The bulk tracking request: the waybills, as a bare array. Pure.
pub fn track_bulk_body(awbs: &[String]) -> Value {
    json!(awbs.iter().take(BULK_MAX).collect::<Vec<_>>())
}

/// The shipment status an SMSA scan means. SMSA's codes vary by service,
/// so the delivered flag and the description decide where the code does
/// not. Pure.
pub fn status_of(scan_type: &str, description: &str, delivered: bool) -> &'static str {
    let d = description.to_ascii_lowercase();
    match scan_type.to_ascii_uppercase().as_str() {
        _ if delivered => "delivered",
        "DL" | "POD" => "delivered",
        "OD" | "OFD" => "out_for_delivery",
        "PU" | "PICKED UP" => "picked_up",
        _ if d.contains("out for delivery") => "out_for_delivery",
        _ if d.contains("not delivered")
            || d.contains("unable to deliver")
            || d.contains("attempt")
            || d.contains("no answer") =>
        {
            "failed_attempt"
        }
        _ if d.contains("refused") || d.contains("rejected") => "refused",
        _ if d.contains("return") => "returned",
        _ if d.contains("delivered") => "delivered",
        _ if d.contains("picked up") || d.contains("collected") => "picked_up",
        _ => "in_transit",
    }
}

/// Saudi time, when a scan names no zone.
const DEFAULT_OFFSET_SECONDS: i32 = 3 * 3600;

/// `+03:00`, `+0300`, `3`, `+3` or `-2.5` as an offset; `None` when absent
/// or unreadable. Pure.
fn offset_of(zone: &str) -> Option<FixedOffset> {
    let z = zone.trim();
    let (sign, rest) = if let Some(rest) = z.strip_prefix('-') {
        (-1, rest)
    } else {
        (1, z.strip_prefix('+').unwrap_or(z))
    };
    if rest.is_empty() {
        return None;
    }
    let hm = |h: &str, m: &str| Some(h.parse::<i32>().ok()? * 3600 + m.parse::<i32>().ok()? * 60);
    let seconds = if let Some((h, m)) = rest.split_once(':') {
        hm(h, m)?
    } else if rest.len() == 4 && rest.bytes().all(|b| b.is_ascii_digit()) {
        let (h, m) = rest.split_at(2);
        hm(h, m)?
    } else if let Some((h, frac)) = rest.split_once('.') {
        // Half-hour zones written as decimals: `5.5`.
        let minutes = format!("0.{frac}").parse::<f64>().ok()?;
        h.parse::<i32>().ok()? * 3600 + if minutes >= 0.5 { 1800 } else { 0 }
    } else {
        rest.parse::<i32>().ok()? * 3600
    };
    FixedOffset::east_opt(sign * seconds)
}

/// A scan's time in Unix milliseconds. Pure.
pub fn scan_time_ms(date_time: &str, zone: &str) -> Option<i64> {
    let raw = date_time.trim();
    if let Ok(at) = DateTime::parse_from_rfc3339(raw) {
        return Some(at.timestamp_millis());
    }
    let naive = [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
    ]
    .iter()
    .find_map(|f| NaiveDateTime::parse_from_str(raw, f).ok())?;
    offset_of(zone)
        .or_else(|| FixedOffset::east_opt(DEFAULT_OFFSET_SECONDS))?
        .from_local_datetime(&naive)
        .single()
        .map(|at| at.timestamp_millis())
}

/// One waybill's latest update, from one tracking object. The event key is
/// the scan's code (or description) and time, so two scans of one code are
/// two events. Pure.
pub fn update_of(tracking: &Value) -> Option<(String, TrackingUpdate)> {
    let awb = tracking["AWB"].as_str()?.trim().to_owned();
    let delivered = tracking["isDelivered"].as_bool() == Some(true);
    let scans = tracking["Scans"].as_array()?;
    let latest = scans.iter().max_by_key(|s| {
        scan_time_ms(
            s["ScanDateTime"].as_str().unwrap_or_default(),
            s["ScanTimeZone"].as_str().unwrap_or_default(),
        )
        .unwrap_or(i64::MIN)
    })?;
    let scan_type = latest["ScanType"].as_str().unwrap_or_default().trim();
    let description = latest["ScanDescription"]
        .as_str()
        .unwrap_or_default()
        .trim();
    let when = latest["ScanDateTime"].as_str().unwrap_or_default().trim();
    let at_ms = scan_time_ms(when, latest["ScanTimeZone"].as_str().unwrap_or_default());
    let label = if scan_type.is_empty() {
        description
    } else {
        scan_type
    };
    let code: String = format!("{label}@{when}").chars().take(100).collect();
    Some((
        awb,
        TrackingUpdate {
            status: status_of(scan_type, description, delivered),
            at_ms,
            code,
        },
    ))
}

/// Reads a single tracking answer for `awb`. Pure.
pub fn parse_track(status: u16, body: &str, awb: &str) -> Option<TrackingUpdate> {
    if !(200..300).contains(&status) {
        return None;
    }
    let json: Value = serde_json::from_str(body).ok()?;
    let one = if json.is_array() {
        json.as_array()?
            .iter()
            .find(|t| t["AWB"].as_str().map(str::trim) == Some(awb))?
            .clone()
    } else {
        json
    };
    update_of(&one)
        .filter(|(found, _)| found == awb)
        .map(|(_, update)| update)
}

/// Reads a bulk tracking answer: each waybill's latest update. Pure.
pub fn parse_track_bulk(status: u16, body: &str) -> Vec<(String, TrackingUpdate)> {
    if !(200..300).contains(&status) {
        return Vec::new();
    }
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(update_of)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn party(name: &str, city: &str) -> Party {
        Party {
            name: name.into(),
            phone: "+966500000000".into(),
            line1: "King Fahd Rd".into(),
            city: city.into(),
            country_code: "SA".into(),
            ..Party::default()
        }
    }

    /// F6-T10: the booking request carries both addresses and the parcel,
    /// and the answer's first parcel waybill is the tracking number.
    #[test]
    fn smsa_book_returns_tracking() {
        let parcel = Parcel {
            reference: "ship-1".into(),
            weight_kg: 2.5,
            pieces: 2,
            description: "Books".into(),
        };
        let body = create_body(
            &party("Store", "Jeddah"),
            &party("Sara", "Riyadh"),
            &parcel,
            "2026-10-25T10:00:00",
            "SAR",
        );
        assert_eq!(body["ConsigneeAddress"]["City"], "Riyadh");
        assert_eq!(body["ShipperAddress"]["ContactName"], "Store");
        assert_eq!(body["OrderNumber"], "ship-1");
        assert_eq!(body["Parcels"], 2);
        assert_eq!(body["Weight"], 2.5);
        assert!(body["CODAmount"].is_number());

        let ok =
            r#"{"sawb":"231200021000","waybills":[{"awb":"231200021001","awbFile":"JVBERi0="}]}"#;
        assert_eq!(
            parse_create(200, ok),
            BookAnswer::Booked {
                tracking_number: "231200021001".into(),
                label_url: None
            }
        );
        let refused = r#"{"errors":{"ConsigneeAddress.City":["The city is not served"]}}"#;
        assert_eq!(
            parse_create(400, refused),
            BookAnswer::Refused {
                message: "ConsigneeAddress.City: The city is not served".into()
            }
        );
        assert_eq!(
            parse_create(401, ""),
            BookAnswer::Refused {
                message: "HTTP 401".into()
            }
        );
        assert_eq!(
            track_url("https://x/", "2312/../00"),
            "https://x/api/track/single/231200"
        );
    }

    /// F6-T10: scans map onto the shipment statuses, and the latest scan
    /// (by its zoned time) is the update.
    #[test]
    fn smsa_status_maps() {
        assert_eq!(status_of("", "Delivered to consignee", false), "delivered");
        assert_eq!(status_of("OD", "", false), "out_for_delivery");
        assert_eq!(
            status_of("", "Not delivered - consignee not available", false),
            "failed_attempt"
        );
        assert_eq!(
            status_of("", "Shipment refused by consignee", false),
            "refused"
        );
        assert_eq!(status_of("", "Returned to shipper", false), "returned");
        assert_eq!(status_of("", "Arrived at hub", false), "in_transit");
        assert_eq!(status_of("XX", "anything", true), "delivered");

        let body = r#"[{"AWB":"231200021001","isDelivered":false,"Scans":[
            {"ScanType":"OD","ScanDescription":"Out for delivery","ScanDateTime":"2026-10-25T09:00:00","ScanTimeZone":"+03:00"},
            {"ScanType":"","ScanDescription":"Arrived at hub","ScanDateTime":"2026-10-24T18:00:00","ScanTimeZone":"+03:00"}]},
            {"AWB":"231200021002","isDelivered":true,"Scans":[
            {"ScanType":"DL","ScanDescription":"Delivered","ScanDateTime":"25/10/2026 11:30","ScanTimeZone":"3"}]}]"#;
        let updates = parse_track_bulk(200, body);
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].0, "231200021001");
        assert_eq!(updates[0].1.status, "out_for_delivery");
        assert_eq!(updates[0].1.code, "OD@2026-10-25T09:00:00");
        assert_eq!(updates[0].1.at_ms, Some(1_792_908_000_000));
        assert_eq!(updates[1].1.status, "delivered");
        assert_eq!(updates[1].1.at_ms, Some(1_792_917_000_000));
        assert_eq!(
            parse_track(200, body, "231200021002").map(|u| u.status),
            Some("delivered")
        );
        assert!(parse_track_bulk(500, body).is_empty());
        assert_eq!(
            track_bulk_body(&["a".into(), "b".into()]),
            json!(["a", "b"])
        );
    }
}
