//! Reading the CSID certificate ZATCA returns (AG2-T3): the issuer name and
//! serial number the XAdES block prints, the public key it certifies and
//! the CA's signature the simplified-invoice QR code carries.
//!
//! ZATCA's `binarySecurityToken` is the certificate's base64 text, base64
//! encoded once more; [`from_token`] undoes that.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::asn1::{big_decimal, children, oid_to_string, read, tag};
use crate::zatca::sign::Certificate;

/// Why a certificate could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CertError {
    #[error("the certificate is not valid base64")]
    Base64,
    #[error("the certificate is not a DER X.509 certificate")]
    Der,
}

/// The certificate in ZATCA's `binarySecurityToken`.
pub fn from_token(token: &str) -> Result<Certificate, CertError> {
    let inner = STANDARD
        .decode(token.trim())
        .map_err(|_| CertError::Base64)?;
    let base64 = String::from_utf8(inner).map_err(|_| CertError::Base64)?;
    parse(base64.trim())
}

fn attribute_name(oid: &str) -> String {
    match oid {
        "2.5.4.3" => "CN".into(),
        "2.5.4.6" => "C".into(),
        "2.5.4.7" => "L".into(),
        "2.5.4.8" => "ST".into(),
        "2.5.4.10" => "O".into(),
        "2.5.4.11" => "OU".into(),
        "0.9.2342.19200300.100.1.25" => "DC".into(),
        "1.2.840.113549.1.9.1" => "E".into(),
        other => other.into(),
    }
}

/// An X.500 name as ZATCA prints it: the last component first, `, `
/// between components (`CN=PRZEINVOICESCA4-CA, DC=extgazt, DC=gov, DC=local`).
fn name_text(name_content: &[u8]) -> Result<String, CertError> {
    let mut parts = Vec::new();
    for rdn in children(name_content).ok_or(CertError::Der)? {
        for atv in children(rdn.content).ok_or(CertError::Der)? {
            let fields = children(atv.content).ok_or(CertError::Der)?;
            let (key, value) = match fields.as_slice() {
                [k, v] if k.tag == tag::OID => (k, v),
                _ => return Err(CertError::Der),
            };
            let text = String::from_utf8_lossy(value.content).into_owned();
            parts.push(format!(
                "{}={}",
                attribute_name(&oid_to_string(key.content)),
                text
            ));
        }
    }
    parts.reverse();
    Ok(parts.join(", "))
}

/// Reads a certificate from its base64 DER.
pub fn parse(base64: &str) -> Result<Certificate, CertError> {
    let der = STANDARD.decode(base64).map_err(|_| CertError::Base64)?;
    let (outer, _) = read(&der).ok_or(CertError::Der)?;
    let top = children(outer.content).ok_or(CertError::Der)?;
    let [tbs, _algorithm, signature] = top.as_slice() else {
        return Err(CertError::Der);
    };
    if signature.tag != tag::BIT_STRING || signature.content.is_empty() {
        return Err(CertError::Der);
    }
    let fields = children(tbs.content).ok_or(CertError::Der)?;
    // An explicit version ([0]) comes first when present.
    let offset = usize::from(fields.first().is_some_and(|f| f.tag == 0xa0));
    let serial = fields.get(offset).ok_or(CertError::Der)?;
    let issuer = fields.get(offset + 2).ok_or(CertError::Der)?;
    if serial.tag != tag::INTEGER || issuer.tag != tag::SEQUENCE {
        return Err(CertError::Der);
    }
    Ok(Certificate {
        base64: base64.to_owned(),
        issuer_name: name_text(issuer.content)?,
        serial_number: big_decimal(serial.content),
        // The BIT STRING's first byte counts unused bits (none for a signature).
        ca_signature: signature.content[1..].to_vec(),
    })
}

/// The DER SubjectPublicKeyInfo the certificate certifies.
pub fn public_key(base64: &str) -> Result<Vec<u8>, CertError> {
    let der = STANDARD.decode(base64).map_err(|_| CertError::Base64)?;
    let (outer, _) = read(&der).ok_or(CertError::Der)?;
    let top = children(outer.content).ok_or(CertError::Der)?;
    let tbs = top.first().ok_or(CertError::Der)?;
    let fields = children(tbs.content).ok_or(CertError::Der)?;
    let offset = usize::from(fields.first().is_some_and(|f| f.tag == 0xa0));
    fields
        .get(offset + 5)
        .filter(|f| f.tag == tag::SEQUENCE)
        .map(|f| f.raw.to_vec())
        .ok_or(CertError::Der)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLES: [&str; 2] = [
        include_str!("testdata/simplified_invoice_signed.xml"),
        include_str!("testdata/standard_invoice_signed.xml"),
    ];

    fn between<'a>(xml: &'a str, open: &str) -> &'a str {
        let start = xml.find(open).expect(open) + open.len();
        &xml[start..start + xml[start..].find('<').unwrap()]
    }

    #[test]
    fn zatca_api_reads_the_samples_certificate_as_zatca_prints_it() {
        for xml in SAMPLES {
            let base64 = between(xml, "<ds:X509Certificate>");
            let cert = parse(base64).unwrap();
            assert_eq!(cert.issuer_name, between(xml, "<ds:X509IssuerName>"));
            assert_eq!(cert.serial_number, between(xml, "<ds:X509SerialNumber>"));
            // The token form round-trips.
            let token = STANDARD.encode(base64);
            assert_eq!(from_token(&token).unwrap(), cert);
        }
    }

    #[test]
    fn zatca_api_the_simplified_samples_qr_carries_the_certificates_ca_signature() {
        let xml = SAMPLES[0];
        let cert = parse(between(xml, "<ds:X509Certificate>")).unwrap();
        let qr_at = xml.find("<cbc:ID>QR</cbc:ID>").unwrap();
        let qr = between(&xml[qr_at..], "mimeCode=\"text/plain\">");
        let tags = crate::zatca::sign::parse_qr(qr).unwrap();
        let tag9 = tags
            .iter()
            .find(|(t, _)| *t == 9)
            .map(|(_, v)| v.clone())
            .unwrap();
        assert_eq!(tag9, cert.ca_signature);
        let tag8 = tags
            .iter()
            .find(|(t, _)| *t == 8)
            .map(|(_, v)| v.clone())
            .unwrap();
        assert_eq!(tag8, public_key(&cert.base64).unwrap());
    }

    #[test]
    fn zatca_api_refuses_what_is_not_a_certificate() {
        assert_eq!(parse("not base64!"), Err(CertError::Base64));
        assert_eq!(
            parse(&STANDARD.encode([0x30, 0x01, 0x00])),
            Err(CertError::Der)
        );
    }
}
