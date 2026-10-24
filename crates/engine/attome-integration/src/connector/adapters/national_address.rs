//! AJ5-T1: Saudi Post (SPL) National Address, to check and standardise an
//! address.
//!
//! Two lookups over SPL's National Address API (v3.1, JSON, `api_key` as a
//! query parameter):
//!
//! - [`NationalAddressClient::by_short_address`]: a short address (four
//!   letters and four digits, `RRRD2929`) to its one address;
//! - [`NationalAddressClient::by_free_text`]: an address as typed to the
//!   matches SPL finds, best first, at most [`MAX_MATCHES`].
//!
//! Each answer is read into a [`Standardised`] address (building number,
//! street, district, city, postal code, additional number, short address,
//! region, coordinates), and [`address_patch`] turns it into the fields of
//! the `address` entity (library-core, D1-T1) to write through the generic
//! update. The API key is a [`Secret`]; an SPL refusal or an answer that is
//! not the expected shape is an error, never an empty match.
//!
//! Checked against recorded answers only: no SPL account is configured here.

use attome_types::AppError;
use serde_json::{Map, Value, json};

use crate::connector::sdk::{Request, Secret, Transport};

/// The most matches a free-text lookup returns.
pub const MAX_MATCHES: usize = 10;

/// SPL's National Address API root.
pub const DEFAULT_BASE_URL: &str = "https://apina.address.gov.sa/NationalAddress/v3.1";

/// An address as SPL standardises it.
#[derive(Debug, Clone, PartialEq)]
pub struct Standardised {
    pub building_number: Option<String>,
    pub street: Option<String>,
    pub district: Option<String>,
    pub city: Option<String>,
    pub postal_code: Option<String>,
    pub additional_number: Option<String>,
    pub short_address: Option<String>,
    pub region: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

/// The language SPL answers in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Arabic,
    English,
}

impl Language {
    fn code(self) -> &'static str {
        match self {
            Language::Arabic => "A",
            Language::English => "E",
        }
    }
}

/// A short address, upper-cased: four letters then four digits.
pub fn short_address(input: &str) -> Option<String> {
    let s: String = input
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    let (letters, digits) = s.split_at_checked(4)?;
    (letters.chars().all(|c| c.is_ascii_uppercase())
        && digits.len() == 4
        && digits.chars().all(|c| c.is_ascii_digit()))
    .then_some(s)
}

/// A National Address connection.
pub struct NationalAddressClient<'a> {
    pub base_url: String,
    pub api_key: Secret,
    pub transport: &'a dyn Transport,
}

impl std::fmt::Debug for NationalAddressClient<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NationalAddressClient")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl<'a> NationalAddressClient<'a> {
    pub fn new(base_url: &str, api_key: Secret, transport: &'a dyn Transport) -> Self {
        NationalAddressClient {
            base_url: base_url.trim_end_matches('/').to_owned(),
            api_key,
            transport,
        }
    }

    async fn get(&self, path: &str, query: &[(&str, &str)]) -> Result<Value, AppError> {
        let mut url = url::Url::parse(&format!("{}/{path}", self.base_url))
            .map_err(|e| AppError::Validation(format!("National Address URL: {e}")))?;
        {
            let mut pairs = url.query_pairs_mut();
            for (k, v) in query {
                pairs.append_pair(k, v);
            }
            pairs.append_pair("format", "json");
            pairs.append_pair("encode", "utf8");
            pairs.append_pair("api_key", self.api_key.wire_value());
        }
        let answer = self
            .transport
            .send(Request {
                method: "GET".into(),
                url: url.into(),
                headers: vec![("Accept".into(), "application/json".into())],
                body: None,
            })
            .await?;
        parse_answer(answer.status, &answer.body)
    }

    /// The address a short address names; `None` when SPL knows none.
    pub async fn by_short_address(
        &self,
        input: &str,
        language: Language,
    ) -> Result<Option<Standardised>, AppError> {
        let code = short_address(input).ok_or_else(|| {
            AppError::Validation("a short address is four letters then four digits".into())
        })?;
        let answer = self
            .get(
                "Address/address-by-short-address",
                &[("shortaddress", &code), ("language", language.code())],
            )
            .await?;
        Ok(addresses(&answer)?.into_iter().next())
    }

    /// The addresses SPL matches to `text`, best first.
    pub async fn by_free_text(
        &self,
        text: &str,
        language: Language,
    ) -> Result<Vec<Standardised>, AppError> {
        let text = text.trim();
        if text.is_empty() || text.chars().count() > 500 {
            return Err(AppError::Validation(
                "an address to look up has 1 to 500 characters".into(),
            ));
        }
        let page_size = MAX_MATCHES.to_string();
        let answer = self
            .get(
                "Address/address-free-text",
                &[
                    ("addressstring", text),
                    ("language", language.code()),
                    ("page", "1"),
                    ("pagesize", &page_size),
                ],
            )
            .await?;
        let mut found = addresses(&answer)?;
        found.truncate(MAX_MATCHES);
        Ok(found)
    }
}

/// An SPL answer as JSON, or why it is refused.
pub fn parse_answer(status: u16, body: &str) -> Result<Value, AppError> {
    if status == 401 || status == 403 {
        return Err(AppError::Validation(
            "National Address refused the API key".into(),
        ));
    }
    if status >= 400 {
        return Err(AppError::internal(format!(
            "National Address answered {status}"
        )));
    }
    let value: Value = serde_json::from_str(body)
        .map_err(|_| AppError::internal("National Address answered no JSON"))?;
    if value.get("success").and_then(Value::as_bool) == Some(false) {
        let message = value["statusdescription"]
            .as_str()
            .or(value["message"].as_str())
            .unwrap_or("no reason given");
        return Err(AppError::Validation(format!(
            "National Address refused the lookup: {message}"
        )));
    }
    Ok(value)
}

fn field(v: &Value, names: &[&str]) -> Option<String> {
    names.iter().find_map(|n| match v.get(*n) {
        Some(Value::String(s)) if !s.trim().is_empty() => Some(s.trim().to_owned()),
        Some(Value::Number(n)) => Some(n.to_string()),
        _ => None,
    })
}

fn coordinate(v: &Value, name: &str) -> Option<f64> {
    match v.get(name) {
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::String(s)) => s.trim().parse().ok(),
        _ => None,
    }
    .filter(|c: &f64| c.is_finite())
}

/// The standardised addresses of an answer (`Addresses`, best first).
pub fn addresses(answer: &Value) -> Result<Vec<Standardised>, AppError> {
    let list = answer
        .get("Addresses")
        .or_else(|| answer.get("addresses"))
        .ok_or_else(|| AppError::internal("National Address answered no address list"))?;
    let Some(list) = list.as_array() else {
        return Ok(Vec::new());
    };
    Ok(list
        .iter()
        .map(|a| Standardised {
            building_number: field(a, &["BuildingNumber"]),
            street: field(a, &["Street"]),
            district: field(a, &["District"]),
            city: field(a, &["City"]),
            postal_code: field(a, &["PostCode", "ZipCode"]),
            additional_number: field(a, &["AdditionalNumber"]),
            short_address: field(a, &["ShortAddress"]).and_then(|s| short_address(&s)),
            region: field(a, &["RegionName", "Region"]),
            latitude: coordinate(a, "Latitude").filter(|l| (-90.0..=90.0).contains(l)),
            longitude: coordinate(a, "Longitude").filter(|l| (-180.0..=180.0).contains(l)),
        })
        .collect())
}

/// The `address` fields a standardised address sets, ready for the generic
/// update; only what SPL returned, so a field it left out keeps its value.
pub fn address_patch(found: &Standardised) -> Map<String, Value> {
    let mut patch = Map::new();
    let mut put = |name: &str, value: &Option<String>| {
        if let Some(v) = value {
            patch.insert(name.to_owned(), json!(v));
        }
    };
    put("building_number", &found.building_number);
    put("street", &found.street);
    put("district", &found.district);
    put("city", &found.city);
    put("postal_code", &found.postal_code);
    put("additional_number", &found.additional_number);
    put("short_address", &found.short_address);
    put("region", &found.region);
    if let (Some(lat), Some(lon)) = (found.latitude, found.longitude) {
        patch.insert("latitude".into(), json!(lat));
        patch.insert("longitude".into(), json!(lon));
    }
    patch.insert("country".into(), json!("SA"));
    patch
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::sdk::Response;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    /// A recorded SPL answer, and the URLs asked for.
    struct Recorded {
        status: u16,
        body: &'static str,
        asked: Mutex<Vec<String>>,
    }

    impl Transport for Recorded {
        fn send<'a>(
            &'a self,
            request: Request,
        ) -> Pin<Box<dyn Future<Output = Result<Response, AppError>> + Send + 'a>> {
            self.asked.lock().unwrap().push(request.url);
            Box::pin(async move {
                Ok(Response {
                    status: self.status,
                    headers: Vec::new(),
                    body: self.body.to_owned(),
                })
            })
        }
    }

    const SHORT: &str = r#"{"totalSearchResults": "1", "success": true, "statusdescription": "SUCCESS",
      "Addresses": [{"Title": null, "Address1": "8228 Imam Abdullah Ibn Saud Ibn Abdulaziz Road, Al Arid District",
        "Address2": "RIYADH 13337 - 2121", "Latitude": "24.81352353", "Longitude": "46.69186622",
        "BuildingNumber": "8228", "Street": "Imam Abdullah Ibn Saud Ibn Abdulaziz Road",
        "District": "Al Arid District", "City": "RIYADH", "PostCode": "13337", "AdditionalNumber": "2121",
        "RegionName": "Riyadh", "ShortAddress": "RRRD2929", "IsPrimaryAddress": "True"}]}"#;

    const NONE: &str = r#"{"totalSearchResults": "0", "success": true, "statusdescription": "SUCCESS", "Addresses": []}"#;
    const REFUSED: &str = r#"{"success": false, "statusdescription": "Invalid API key"}"#;

    fn run<T>(f: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn a_short_address_is_four_letters_then_four_digits() {
        assert_eq!(short_address(" rrrd 2929 ").as_deref(), Some("RRRD2929"));
        assert_eq!(short_address("RRR2929"), None);
        assert_eq!(short_address("RRRDX929"), None);
        assert_eq!(short_address("١٢٣٤ABCD"), None);
    }

    #[test]
    fn a_short_address_lookup_standardises_the_address() {
        let t = Recorded {
            status: 200,
            body: SHORT,
            asked: Mutex::new(Vec::new()),
        };
        let client = NationalAddressClient::new(DEFAULT_BASE_URL, Secret::new("k-123"), &t);
        let found = run(client.by_short_address("rrrd2929", Language::English))
            .unwrap()
            .unwrap();
        assert_eq!(found.building_number.as_deref(), Some("8228"));
        assert_eq!(found.postal_code.as_deref(), Some("13337"));
        assert_eq!(found.short_address.as_deref(), Some("RRRD2929"));
        assert!((found.latitude.unwrap() - 24.813_523_53).abs() < 1e-9);
        let url = t.asked.lock().unwrap()[0].clone();
        assert!(url.contains("shortaddress=RRRD2929"), "{url}");
        assert!(url.contains("language=E"), "{url}");

        let patch = address_patch(&found);
        assert_eq!(patch["city"], "RIYADH");
        assert_eq!(patch["additional_number"], "2121");
        assert_eq!(patch["country"], "SA");
        assert!(patch["longitude"].as_f64().is_some());
    }

    #[test]
    fn no_match_refusals_and_bad_input() {
        let none = Recorded {
            status: 200,
            body: NONE,
            asked: Mutex::new(Vec::new()),
        };
        let client = NationalAddressClient::new(DEFAULT_BASE_URL, Secret::new("k"), &none);
        assert_eq!(
            run(client.by_short_address("ABCD1234", Language::Arabic)).unwrap(),
            None
        );
        assert!(run(client.by_free_text("  ", Language::Arabic)).is_err());
        assert!(run(client.by_short_address("12", Language::Arabic)).is_err());
        assert!(
            none.asked.lock().unwrap().len() == 1,
            "bad input never reaches SPL"
        );

        let refused = Recorded {
            status: 200,
            body: REFUSED,
            asked: Mutex::new(Vec::new()),
        };
        let client = NationalAddressClient::new(DEFAULT_BASE_URL, Secret::new("k"), &refused);
        let err = run(client.by_free_text("8228 Al Arid, Riyadh", Language::English)).unwrap_err();
        assert!(
            matches!(err, AppError::Validation(ref m) if m.contains("Invalid API key")),
            "{err:?}"
        );

        let denied = Recorded {
            status: 401,
            body: "",
            asked: Mutex::new(Vec::new()),
        };
        let client = NationalAddressClient::new(DEFAULT_BASE_URL, Secret::new("k"), &denied);
        assert!(matches!(
            run(client.by_free_text("Riyadh", Language::English)),
            Err(AppError::Validation(_))
        ));
    }

    #[test]
    fn coordinates_out_of_range_are_dropped() {
        let answer: Value = serde_json::from_str(
            r#"{"Addresses": [{"City": "JEDDAH", "Latitude": "190", "Longitude": "39.1"}]}"#,
        )
        .unwrap();
        let found = &addresses(&answer).unwrap()[0];
        assert_eq!(found.latitude, None);
        let patch = address_patch(found);
        assert!(patch.get("latitude").is_none() && patch.get("longitude").is_none());
    }
}
