//! The certificate signing request a device sends to onboard (AG2-T3), with
//! the fields ZATCA's onboarding guide requires:
//!
//! - subject: `C` (country), `OU` (branch or organisation unit), `O`
//!   (taxpayer name), `CN` (the device's common name);
//! - the certificate template name extension (`1.3.6.1.4.1.311.20.2`):
//!   `TSTZATCA-Code-Signing` for the developer portal, `PREZATCA-Code-Signing`
//!   for simulation, `ZATCA-Code-Signing` for production;
//! - subject alternative names as a directory name: `SN` the device's
//!   serial (`1-<solution>|2-<model>|3-<serial>`), `UID` the VAT number,
//!   `title` the invoice types it issues (four digits: standard,
//!   simplified, then two reserved: `1100` both), `registeredAddress` and
//!   `businessCategory`.
//!
//! Signed ECDSA-SHA256 with the device's key. ZATCA takes the PEM text,
//! base64-encoded once more ([`Csr::for_api`]).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::asn1::{bit_string, context, integer, oid, printable, seq, set, utf8};
use crate::zatca::sign::{DeviceKey, SignError};

/// Which ZATCA environment the device onboards to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Environment {
    /// The developer portal sandbox (fixed OTPs, no real taxpayer).
    Sandbox,
    /// Simulation: real taxpayer, test invoices.
    Simulation,
    Production,
}

impl Environment {
    pub fn template_name(self) -> &'static str {
        match self {
            Self::Sandbox => "TSTZATCA-Code-Signing",
            Self::Simulation => "PREZATCA-Code-Signing",
            Self::Production => "ZATCA-Code-Signing",
        }
    }

    pub fn base_url(self) -> &'static str {
        match self {
            Self::Sandbox => "https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal",
            Self::Simulation => "https://gw-fatoora.zatca.gov.sa/e-invoicing/simulation",
            Self::Production => "https://gw-fatoora.zatca.gov.sa/e-invoicing/core",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sandbox => "sandbox",
            Self::Simulation => "simulation",
            Self::Production => "production",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "sandbox" => Some(Self::Sandbox),
            "simulation" => Some(Self::Simulation),
            "production" => Some(Self::Production),
            _ => None,
        }
    }
}

/// What the request says about the device and the taxpayer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsrFields {
    pub environment: Environment,
    /// The device's common name.
    pub common_name: String,
    /// `1-<solution>|2-<model>|3-<serial>`.
    pub serial_number: String,
    /// Fifteen digits.
    pub vat_number: String,
    pub organization_unit: String,
    pub organization: String,
    /// ISO 3166-1 alpha-2 (`SA`).
    pub country: String,
    /// Four digits, e.g. `1100` for standard and simplified invoices.
    pub invoice_types: String,
    pub location: String,
    pub industry: String,
}

/// A signed certificate signing request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Csr {
    pub der: Vec<u8>,
}

fn attribute(oid_text: &str, value: Vec<u8>) -> Vec<u8> {
    set(&[seq(&[oid(oid_text), value])])
}

/// Writes and signs the request.
pub fn build(fields: &CsrFields, key: &DeviceKey) -> Result<Csr, SignError> {
    let subject = seq(&[
        attribute("2.5.4.6", printable(&fields.country)),
        attribute("2.5.4.11", utf8(&fields.organization_unit)),
        attribute("2.5.4.10", utf8(&fields.organization)),
        attribute("2.5.4.3", utf8(&fields.common_name)),
    ]);
    let alt_name = seq(&[context(
        4,
        &seq(&[
            attribute("2.5.4.4", utf8(&fields.serial_number)),
            attribute("0.9.2342.19200300.100.1.1", utf8(&fields.vat_number)),
            attribute("2.5.4.12", utf8(&fields.invoice_types)),
            attribute("2.5.4.26", utf8(&fields.location)),
            attribute("2.5.4.15", utf8(&fields.industry)),
        ]),
    )]);
    let extensions = seq(&[
        seq(&[
            oid("1.3.6.1.4.1.311.20.2"),
            crate::asn1::tlv(
                crate::asn1::tag::OCTET_STRING,
                &printable(fields.environment.template_name()),
            ),
        ]),
        seq(&[
            oid("2.5.29.17"),
            crate::asn1::tlv(crate::asn1::tag::OCTET_STRING, &alt_name),
        ]),
    ]);
    let attributes = context(0, &seq(&[oid("1.2.840.113549.1.9.14"), set(&[extensions])]));
    let info = seq(&[integer(0), subject, key.public_key_der()?, attributes]);
    let signature = STANDARD
        .decode(key.sign(&info))
        .map_err(|_| SignError::Key)?;
    let der = seq(&[
        info,
        seq(&[oid("1.2.840.10045.4.3.2")]),
        bit_string(&signature),
    ]);
    Ok(Csr { der })
}

impl Csr {
    /// The PEM text.
    pub fn pem(&self) -> String {
        let body = STANDARD.encode(&self.der);
        let mut out = String::from("-----BEGIN CERTIFICATE REQUEST-----\n");
        for chunk in body.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE REQUEST-----\n");
        out
    }

    /// What the compliance CSID call takes: the PEM, base64 once more.
    pub fn for_api(&self) -> String {
        STANDARD.encode(self.pem())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::asn1::{children, oid_to_string, read};

    pub(crate) fn fields() -> CsrFields {
        CsrFields {
            environment: Environment::Sandbox,
            common_name: "Attome-EGS-1".into(),
            serial_number: "1-Attome|2-v2|3-ed22f1d8-e6a2-1118-9b58-d9a8f11e445f".into(),
            vat_number: "399999999900003".into(),
            organization_unit: "Riyadh Branch".into(),
            organization: "شركة أتوم".into(),
            country: "SA".into(),
            invoice_types: "1100".into(),
            location: "RRRD2929".into(),
            industry: "Software".into(),
        }
    }

    #[test]
    fn zatca_api_csr_carries_zatcas_fields_and_a_signature_that_verifies() {
        let key = DeviceKey::generate();
        let csr = build(&fields(), &key).unwrap();
        let (outer, rest) = read(&csr.der).unwrap();
        assert!(rest.is_empty());
        let parts = children(outer.content).unwrap();
        assert_eq!(parts.len(), 3);
        // The signature is the device key's over the request info.
        let signature = &parts[2].content[1..];
        assert!(crate::zatca::sign::verify(
            &key.public_key_der().unwrap(),
            parts[0].raw,
            &STANDARD.encode(signature),
        ));
        assert_eq!(
            oid_to_string(children(parts[1].content).unwrap()[0].content),
            "1.2.840.10045.4.3.2"
        );
        let text = String::from_utf8_lossy(&csr.der);
        assert!(text.contains("TSTZATCA-Code-Signing"));
        assert!(text.contains("399999999900003"));
        assert!(
            csr.pem()
                .starts_with("-----BEGIN CERTIFICATE REQUEST-----\n")
        );
        assert_eq!(
            String::from_utf8(STANDARD.decode(csr.for_api()).unwrap()).unwrap(),
            csr.pem()
        );
        assert_eq!(
            Environment::parse("simulation").unwrap().template_name(),
            "PREZATCA-Code-Signing"
        );
    }
}
