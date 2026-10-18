//! Stamping an invoice (roadmap AG2-T2): the device's ECDSA secp256k1
//! signature over the invoice hash, the XAdES block ZATCA reads, and the QR
//! code.
//!
//! - The signature is ECDSA with SHA-256 over the invoice digest (the raw
//!   32 bytes whose base64 is the invoice hash), DER-encoded, then base64.
//! - The certificate digest is the base64 of the hex SHA-256 of the
//!   certificate's base64 text, and the signed-properties digest the base64
//!   of the hex SHA-256 of the `xades:SignedProperties` element as ZATCA's
//!   validator sees it in place (the fixed layout [`signed_properties`]
//!   writes). Both reproduce ZATCA's sample invoices.
//! - The QR code is a base64 TLV: 1 seller name, 2 seller VAT number, 3 issue
//!   timestamp, 4 total with VAT, 5 VAT total, 6 invoice hash, 7 signature,
//!   8 the device's public key (DER), and for a simplified invoice 9 the
//!   CSID certificate's signature by ZATCA's CA.
//!
//! Keys are pure Rust (k256): no native library (V2-D471). A device keeps
//! one key and one hash chain; the key is stored encrypted under
//! `einvoice.key_encryption_key` ([`super::super::crypto`]).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chrono::NaiveDateTime;
use k256::ecdsa::signature::{Signer, Verifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use sha2::{Digest, Sha256};

use super::hash::invoice_digest;
use super::xml::{Profile, Stamp, XmlError, ZatcaInvoice, amount, invoice_xml, totals};

/// Why an invoice could not be stamped.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("{0}")]
    Xml(#[from] XmlError),
    #[error("{0}")]
    Canonical(#[from] super::c14n::C14nError),
    #[error("the device key could not be read")]
    Key,
    #[error("a QR field is longer than 255 bytes")]
    QrFieldTooLong,
}

/// A device's signing key.
pub struct DeviceKey {
    key: SigningKey,
}

impl std::fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceKey").finish_non_exhaustive()
    }
}

impl DeviceKey {
    /// A new key from the operating system's random source.
    pub fn generate() -> Self {
        Self {
            key: SigningKey::random(&mut rand::rngs::OsRng),
        }
    }

    /// The key from its PKCS#8 DER form (as stored, decrypted).
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, SignError> {
        SigningKey::from_pkcs8_der(der)
            .map(|key| Self { key })
            .map_err(|_| SignError::Key)
    }

    /// The key's PKCS#8 DER form, to encrypt and store. Zeroed on drop.
    pub fn to_pkcs8_der(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, SignError> {
        self.key
            .to_pkcs8_der()
            .map(|doc| zeroize::Zeroizing::new(doc.as_bytes().to_vec()))
            .map_err(|_| SignError::Key)
    }

    /// The public key as DER SubjectPublicKeyInfo (QR tag 8, and the CSR).
    pub fn public_key_der(&self) -> Result<Vec<u8>, SignError> {
        self.key
            .verifying_key()
            .to_public_key_der()
            .map(|doc| doc.as_bytes().to_vec())
            .map_err(|_| SignError::Key)
    }

    /// ECDSA-SHA256 over `message`, DER, base64.
    pub fn sign(&self, message: &[u8]) -> String {
        let signature: Signature = self.key.sign(message);
        STANDARD.encode(signature.to_der().as_bytes())
    }
}

/// Whether `signature` (base64 DER) is `public_key`'s (DER
/// SubjectPublicKeyInfo) ECDSA-SHA256 signature over `message`, either S.
pub fn verify(public_key_der: &[u8], message: &[u8], signature: &str) -> bool {
    let Ok(key) = VerifyingKey::from_public_key_der(public_key_der) else {
        return false;
    };
    let Ok(bytes) = STANDARD.decode(signature) else {
        return false;
    };
    let Ok(signature) = Signature::from_der(&bytes) else {
        return false;
    };
    // ECDSA admits two S values per signature; k256 only verifies the low
    // one, ZATCA's Java stack signs either (one of its samples is high-S).
    let signature = signature.normalize_s().unwrap_or(signature);
    key.verify(message, &signature).is_ok()
}

/// The device's CSID certificate, as onboarding keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// The certificate, base64 DER (ZATCA's binarySecurityToken, decoded once).
    pub base64: String,
    /// The issuer as ZATCA prints it, e.g. `CN=PRZEINVOICESCA4-CA, DC=extgazt, DC=gov, DC=local`.
    pub issuer_name: String,
    /// The serial number, in decimal.
    pub serial_number: String,
    /// The CA's signature over the certificate (QR tag 9).
    pub ca_signature: Vec<u8>,
}

/// base64 of the hex SHA-256 of `data`: how ZATCA writes these digests.
fn hex_digest_b64(data: &[u8]) -> String {
    let hex: String = Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    STANDARD.encode(hex)
}

impl Certificate {
    /// The certificate digest in `xades:CertDigest`.
    pub fn digest(&self) -> String {
        hex_digest_b64(self.base64.as_bytes())
    }
}

const DS: &str = "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"";

/// `xades:SignedProperties` as the validator hashes it.
pub fn signed_properties(signing_time: &str, cert: &Certificate) -> String {
    format!(
        "<xades:SignedProperties xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\" Id=\"xadesSignedProperties\">\n\
         {i32}<xades:SignedSignatureProperties>\n\
         {i36}<xades:SigningTime>{signing_time}</xades:SigningTime>\n\
         {i36}<xades:SigningCertificate>\n\
         {i40}<xades:Cert>\n\
         {i44}<xades:CertDigest>\n\
         {i48}<ds:DigestMethod {DS} Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n\
         {i48}<ds:DigestValue {DS}>{digest}</ds:DigestValue>\n\
         {i44}</xades:CertDigest>\n\
         {i44}<xades:IssuerSerial>\n\
         {i48}<ds:X509IssuerName {DS}>{issuer}</ds:X509IssuerName>\n\
         {i48}<ds:X509SerialNumber {DS}>{serial}</ds:X509SerialNumber>\n\
         {i44}</xades:IssuerSerial>\n\
         {i40}</xades:Cert>\n\
         {i36}</xades:SigningCertificate>\n\
         {i32}</xades:SignedSignatureProperties>\n\
         {i28}</xades:SignedProperties>",
        i28 = " ".repeat(28),
        i32 = " ".repeat(32),
        i36 = " ".repeat(36),
        i40 = " ".repeat(40),
        i44 = " ".repeat(44),
        i48 = " ".repeat(48),
        digest = cert.digest(),
        issuer = xml_text(&cert.issuer_name),
        serial = xml_text(&cert.serial_number),
    )
}

/// The signed-properties digest.
pub fn signed_properties_digest(signing_time: &str, cert: &Certificate) -> String {
    hex_digest_b64(signed_properties(signing_time, cert).as_bytes())
}

fn xml_text(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The `ext:UBLExtensions` element, in the layout that keeps the signed
/// properties where their digest says.
pub fn extensions(
    invoice_hash: &str,
    signature: &str,
    signing_time: &str,
    cert: &Certificate,
) -> String {
    let props_digest = signed_properties_digest(signing_time, cert);
    let i = |n: usize| " ".repeat(n);
    let xpath = "http://www.w3.org/TR/1999/REC-xpath-19991116";
    let sha = "http://www.w3.org/2001/04/xmlenc#sha256";
    let mut out = String::new();
    let mut push = |indent: usize, text: &str| {
        out.push_str(&i(indent));
        out.push_str(text);
        out.push('\n');
    };
    push(0, "<ext:UBLExtensions><ext:UBLExtension>");
    push(
        4,
        "<ext:ExtensionURI>urn:oasis:names:specification:ubl:dsig:enveloped:xades</ext:ExtensionURI>",
    );
    push(4, "<ext:ExtensionContent>");
    push(
        8,
        "<sig:UBLDocumentSignatures xmlns:sig=\"urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2\" xmlns:sac=\"urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2\" xmlns:sbc=\"urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2\">",
    );
    push(12, "<sac:SignatureInformation>");
    push(
        16,
        "<cbc:ID>urn:oasis:names:specification:ubl:signature:1</cbc:ID>",
    );
    push(
        16,
        "<sbc:ReferencedSignatureID>urn:oasis:names:specification:ubl:signature:Invoice</sbc:ReferencedSignatureID>",
    );
    push(16, &format!("<ds:Signature {DS} Id=\"signature\">"));
    push(20, "<ds:SignedInfo>");
    push(
        24,
        "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2006/12/xml-c14n11\"/>",
    );
    push(
        24,
        "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256\"/>",
    );
    push(24, "<ds:Reference Id=\"invoiceSignedData\" URI=\"\">");
    push(28, "<ds:Transforms>");
    for path in [
        "not(//ancestor-or-self::ext:UBLExtensions)",
        "not(//ancestor-or-self::cac:Signature)",
        "not(//ancestor-or-self::cac:AdditionalDocumentReference[cbc:ID='QR'])",
    ] {
        push(32, &format!("<ds:Transform Algorithm=\"{xpath}\">"));
        push(36, &format!("<ds:XPath>{path}</ds:XPath>"));
        push(32, "</ds:Transform>");
    }
    push(
        32,
        "<ds:Transform Algorithm=\"http://www.w3.org/2006/12/xml-c14n11\"/>",
    );
    push(28, "</ds:Transforms>");
    push(28, &format!("<ds:DigestMethod Algorithm=\"{sha}\"/>"));
    push(
        28,
        &format!("<ds:DigestValue>{invoice_hash}</ds:DigestValue>"),
    );
    push(24, "</ds:Reference>");
    push(
        24,
        "<ds:Reference Type=\"http://www.w3.org/2000/09/xmldsig#SignatureProperties\" URI=\"#xadesSignedProperties\">",
    );
    push(28, &format!("<ds:DigestMethod Algorithm=\"{sha}\"/>"));
    push(
        28,
        &format!("<ds:DigestValue>{props_digest}</ds:DigestValue>"),
    );
    push(24, "</ds:Reference>");
    push(20, "</ds:SignedInfo>");
    push(
        20,
        &format!("<ds:SignatureValue>{signature}</ds:SignatureValue>"),
    );
    push(20, "<ds:KeyInfo>");
    push(24, "<ds:X509Data>");
    push(
        28,
        &format!("<ds:X509Certificate>{}</ds:X509Certificate>", cert.base64),
    );
    push(24, "</ds:X509Data>");
    push(20, "</ds:KeyInfo>");
    push(20, "<ds:Object>");
    push(
        24,
        "<xades:QualifyingProperties xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\" Target=\"signature\">",
    );
    push(28, "<xades:SignedProperties Id=\"xadesSignedProperties\">");
    push(32, "<xades:SignedSignatureProperties>");
    push(
        36,
        &format!("<xades:SigningTime>{signing_time}</xades:SigningTime>"),
    );
    push(36, "<xades:SigningCertificate>");
    push(40, "<xades:Cert>");
    push(44, "<xades:CertDigest>");
    push(48, &format!("<ds:DigestMethod Algorithm=\"{sha}\"/>"));
    push(
        48,
        &format!("<ds:DigestValue>{}</ds:DigestValue>", cert.digest()),
    );
    push(44, "</xades:CertDigest>");
    push(44, "<xades:IssuerSerial>");
    push(
        48,
        &format!(
            "<ds:X509IssuerName>{}</ds:X509IssuerName>",
            xml_text(&cert.issuer_name)
        ),
    );
    push(
        48,
        &format!(
            "<ds:X509SerialNumber>{}</ds:X509SerialNumber>",
            xml_text(&cert.serial_number)
        ),
    );
    push(44, "</xades:IssuerSerial>");
    push(40, "</xades:Cert>");
    push(36, "</xades:SigningCertificate>");
    push(32, "</xades:SignedSignatureProperties>");
    push(28, "</xades:SignedProperties>");
    push(24, "</xades:QualifyingProperties>");
    push(20, "</ds:Object>");
    push(16, "</ds:Signature>");
    push(12, "</sac:SignatureInformation>");
    push(8, "</sig:UBLDocumentSignatures>");
    push(4, "</ext:ExtensionContent>");
    push(0, "</ext:UBLExtension>");
    out.push_str("</ext:UBLExtensions>");
    out
}

/// What the QR code carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrFields {
    pub seller_name: String,
    pub vat_number: String,
    /// `YYYY-MM-DDTHH:MM:SSZ`.
    pub timestamp: String,
    pub total: String,
    pub vat_total: String,
    pub invoice_hash: String,
    pub signature: String,
    pub public_key: Vec<u8>,
    /// Simplified invoices only.
    pub ca_signature: Option<Vec<u8>>,
}

/// The QR code: base64 of the TLV.
pub fn qr(fields: &QrFields) -> Result<String, SignError> {
    let mut tlv = Vec::new();
    let mut put = |tag: u8, value: &[u8]| -> Result<(), SignError> {
        let len = u8::try_from(value.len()).map_err(|_| SignError::QrFieldTooLong)?;
        tlv.push(tag);
        tlv.push(len);
        tlv.extend_from_slice(value);
        Ok(())
    };
    put(1, fields.seller_name.as_bytes())?;
    put(2, fields.vat_number.as_bytes())?;
    put(3, fields.timestamp.as_bytes())?;
    put(4, fields.total.as_bytes())?;
    put(5, fields.vat_total.as_bytes())?;
    put(6, fields.invoice_hash.as_bytes())?;
    put(7, fields.signature.as_bytes())?;
    put(8, &fields.public_key)?;
    if let Some(ca) = &fields.ca_signature {
        put(9, ca)?;
    }
    Ok(STANDARD.encode(tlv))
}

/// The tags of a QR code, in order.
pub fn parse_qr(qr: &str) -> Option<Vec<(u8, Vec<u8>)>> {
    let bytes = STANDARD.decode(qr).ok()?;
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let tag = *bytes.get(i)?;
        let len = usize::from(*bytes.get(i + 1)?);
        let value = bytes.get(i + 2..i + 2 + len)?.to_vec();
        out.push((tag, value));
        i += 2 + len;
    }
    Some(out)
}

/// A stamped invoice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamped {
    /// The invoice XML ZATCA receives.
    pub xml: String,
    /// Its hash: the next document's PIH on this device.
    pub hash: String,
    pub qr: String,
}

/// Stamps an invoice with the device's key and certificate at
/// `signing_time` (UTC).
pub fn stamp(
    inv: &ZatcaInvoice,
    key: &DeviceKey,
    cert: &Certificate,
    signing_time: NaiveDateTime,
) -> Result<Stamped, SignError> {
    let unstamped = invoice_xml(inv, &Stamp::default())?;
    let digest = invoice_digest(&unstamped)?;
    let hash = STANDARD.encode(digest);
    let signature = key.sign(&digest);
    let time = signing_time.format("%Y-%m-%dT%H:%M:%S").to_string();
    let (net, vat) = totals(inv);
    let qr = qr(&QrFields {
        seller_name: inv.seller.registration_name.clone(),
        vat_number: inv.seller.vat_number.clone().unwrap_or_default(),
        timestamp: format!(
            "{}T{}Z",
            inv.issue_date.format("%Y-%m-%d"),
            inv.issue_time.format("%H:%M:%S")
        ),
        total: amount(net + vat),
        vat_total: amount(vat),
        invoice_hash: hash.clone(),
        signature: signature.clone(),
        public_key: key.public_key_der()?,
        ca_signature: (inv.profile == Profile::Simplified).then(|| cert.ca_signature.clone()),
    })?;
    let xml = invoice_xml(
        inv,
        &Stamp {
            extensions: Some(extensions(&hash, &signature, &time, cert)),
            qr: Some(qr.clone()),
        },
    )?;
    Ok(Stamped { xml, hash, qr })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zatca::hash::invoice_hash;

    fn between<'a>(xml: &'a str, open: &str, close: &str) -> &'a str {
        let start = xml.find(open).expect(open) + open.len();
        let end = xml[start..].find(close).expect(close);
        &xml[start..start + end]
    }

    fn sample_cert(xml: &str) -> Certificate {
        Certificate {
            base64: between(xml, "<ds:X509Certificate>", "<").to_owned(),
            issuer_name: between(xml, "<ds:X509IssuerName>", "<").to_owned(),
            serial_number: between(xml, "<ds:X509SerialNumber>", "<").to_owned(),
            ca_signature: Vec::new(),
        }
    }

    fn digests(xml: &str) -> Vec<&str> {
        xml.match_indices("<ds:DigestValue>")
            .map(|(i, m)| {
                let start = i + m.len();
                &xml[start..start + xml[start..].find('<').unwrap()]
            })
            .collect()
    }

    const SAMPLES: [&str; 2] = [
        include_str!("testdata/simplified_invoice_signed.xml"),
        include_str!("testdata/standard_invoice_signed.xml"),
    ];

    #[test]
    fn zatca_sign_reproduces_the_samples_certificate_and_properties_digests() {
        for xml in SAMPLES {
            let cert = sample_cert(xml);
            let d = digests(xml);
            assert_eq!(cert.digest(), d[2]);
            let time = between(xml, "<xades:SigningTime>", "<");
            assert_eq!(signed_properties_digest(time, &cert), d[1]);
        }
    }

    #[test]
    fn zatca_sign_samples_signatures_verify_and_their_qr_reads() {
        for xml in SAMPLES {
            let qr_start = xml.find("<cbc:ID>QR</cbc:ID>").expect("the QR reference");
            let qr_text = between(&xml[qr_start..], "mimeCode=\"text/plain\">", "<");
            let tags = parse_qr(qr_text).expect("a QR TLV");
            let get = |t: u8| {
                tags.iter()
                    .find(|(tag, _)| *tag == t)
                    .map(|(_, v)| v.clone())
                    .unwrap()
            };
            let hash = String::from_utf8(get(6)).unwrap();
            assert_eq!(hash, invoice_hash(xml).unwrap());
            let signature = String::from_utf8(get(7)).unwrap();
            assert_eq!(signature, between(xml, "<ds:SignatureValue>", "<"));
            let digest = STANDARD.decode(&hash).unwrap();
            assert!(
                verify(&get(8), &digest, &signature),
                "the sample's signature verifies"
            );
            assert!(!verify(&get(8), b"something else", &signature));
        }
    }

    #[test]
    fn zatca_sign_stamps_an_invoice_that_verifies() {
        let inv = crate::zatca::xml::tests::sample();
        let key = DeviceKey::generate();
        let cert = sample_cert(SAMPLES[1]);
        let time =
            NaiveDateTime::parse_from_str("2026-10-18T09:30:05", "%Y-%m-%dT%H:%M:%S").unwrap();
        let stamped = stamp(&inv, &key, &cert, time).unwrap();
        // The stamped document hashes to what it was signed over.
        assert_eq!(invoice_hash(&stamped.xml).unwrap(), stamped.hash);
        let d = digests(&stamped.xml);
        assert_eq!(d[0], stamped.hash);
        assert_eq!(d[1], signed_properties_digest("2026-10-18T09:30:05", &cert));
        // The QR carries the hash, the signature and the key, which verify.
        let tags = parse_qr(&stamped.qr).unwrap();
        let tag = |t: u8| tags.iter().find(|(x, _)| *x == t).map(|(_, v)| v.clone());
        assert_eq!(String::from_utf8(tag(4).unwrap()).unwrap(), "268.50");
        assert_eq!(String::from_utf8(tag(5).unwrap()).unwrap(), "28.50");
        assert_eq!(tag(9), None, "a standard invoice carries no CA signature");
        let signature = String::from_utf8(tag(7).unwrap()).unwrap();
        let digest = STANDARD.decode(&stamped.hash).unwrap();
        assert!(verify(&tag(8).unwrap(), &digest, &signature));
        assert!(stamped.xml.contains(&format!(
            ">{}</cbc:EmbeddedDocumentBinaryObject>",
            stamped.qr
        )));
        // The key survives its stored form.
        let restored = DeviceKey::from_pkcs8_der(&key.to_pkcs8_der().unwrap()).unwrap();
        assert_eq!(
            restored.public_key_der().unwrap(),
            key.public_key_der().unwrap()
        );
    }

    #[test]
    fn zatca_sign_simplified_qr_carries_the_ca_signature() {
        let mut inv = crate::zatca::xml::tests::sample();
        inv.profile = Profile::Simplified;
        let mut cert = sample_cert(SAMPLES[0]);
        cert.ca_signature = vec![0x30, 0x45, 0x02];
        let time =
            NaiveDateTime::parse_from_str("2026-10-18T09:30:05", "%Y-%m-%dT%H:%M:%S").unwrap();
        let stamped = stamp(&inv, &DeviceKey::generate(), &cert, time).unwrap();
        let tags = parse_qr(&stamped.qr).unwrap();
        assert_eq!(tags.last().unwrap(), &(9, vec![0x30, 0x45, 0x02]));
    }
}
