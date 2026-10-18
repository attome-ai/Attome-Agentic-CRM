//! The invoice hash and the previous-invoice-hash chain.
//!
//! The hash is SHA-256 over the canonical invoice without its signature
//! parts ([`super::c14n`]), written in base64. Each device numbers its
//! documents (the invoice counter value, ICV, from 1) and puts the previous
//! document's hash in the next one (PIH); the first document of a device
//! carries [`FIRST_PIH`], which is the base64 of the hex SHA-256 of `"0"`,
//! as ZATCA specifies. A device's chain must never fork: the caller stores
//! [`ChainState`] per device and advances it in the transaction that keeps
//! the document.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::c14n::{C14nError, Removal, canonicalize};

/// The PIH of a device's first document.
pub const FIRST_PIH: &str =
    "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==";

/// The SHA-256 of the canonical invoice without its signature parts.
pub fn invoice_digest(xml: &str) -> Result<[u8; 32], C14nError> {
    let canonical = canonicalize(xml, Removal::InvoiceHash)?;
    Ok(Sha256::digest(canonical.as_bytes()).into())
}

/// The invoice hash, base64.
pub fn invoice_hash(xml: &str) -> Result<String, C14nError> {
    Ok(STANDARD.encode(invoice_digest(xml)?))
}

/// Where a device's chain stands: the last counter value and hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainState {
    pub last_icv: u64,
    pub last_hash: String,
}

impl Default for ChainState {
    fn default() -> Self {
        Self {
            last_icv: 0,
            last_hash: FIRST_PIH.to_owned(),
        }
    }
}

impl ChainState {
    /// The ICV and PIH the next document takes.
    pub fn next(&self) -> (u64, String) {
        (self.last_icv + 1, self.last_hash.clone())
    }

    /// The state after a document with `icv` and `hash` is kept.
    pub fn advance(&self, icv: u64, hash: String) -> Result<Self, ChainError> {
        if icv != self.last_icv + 1 {
            return Err(ChainError::OutOfOrder {
                expected: self.last_icv + 1,
                got: icv,
            });
        }
        Ok(Self {
            last_icv: icv,
            last_hash: hash,
        })
    }
}

/// A document that does not follow its device's chain.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    #[error("the device's next counter value is {expected}, not {got}")]
    OutOfOrder { expected: u64, got: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ZATCA's sample invoices (`testdata/README.md`): the digest the signed
    /// file carries for `invoiceSignedData` is the invoice hash.
    fn signed_digest(xml: &str) -> &str {
        let start = xml
            .find("Id=\"invoiceSignedData\"")
            .expect("the invoice reference");
        let rest = &xml[start..];
        let open = rest.find("<ds:DigestValue>").expect("its digest") + "<ds:DigestValue>".len();
        let close = rest[open..].find('<').expect("the digest's end");
        &rest[open..open + close]
    }

    #[test]
    fn zatca_xml_hash_reproduces_the_simplified_sample() {
        let xml = include_str!("testdata/simplified_invoice_signed.xml");
        assert_eq!(invoice_hash(xml).unwrap(), signed_digest(xml));
        assert_eq!(
            signed_digest(xml),
            "7HWvwzSMv7IEh3pIhuX4xQNPqBWbUm6RhdPjSKPF0xM="
        );
    }

    #[test]
    fn zatca_xml_hash_reproduces_the_standard_sample() {
        let xml = include_str!("testdata/standard_invoice_signed.xml");
        assert_eq!(invoice_hash(xml).unwrap(), signed_digest(xml));
    }

    #[test]
    fn zatca_xml_first_pih_is_the_hash_of_zero() {
        let hex: String = Sha256::digest(b"0")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(STANDARD.encode(hex), FIRST_PIH);
    }

    #[test]
    fn zatca_xml_stamping_never_changes_the_hash() {
        use super::super::xml::{Stamp, invoice_xml, tests::sample};
        let unstamped = invoice_xml(&sample(), &Stamp::default()).unwrap();
        let stamped = invoice_xml(
            &sample(),
            &Stamp {
                extensions: Some(
                    "<ext:UBLExtensions><ext:UBLExtension><ext:ExtensionURI>x</ext:ExtensionURI></ext:UBLExtension></ext:UBLExtensions>"
                        .into(),
                ),
                qr: Some("AQhBdHRvbWU=".into()),
            },
        )
        .unwrap();
        assert_ne!(unstamped, stamped);
        assert_eq!(
            invoice_hash(&unstamped).unwrap(),
            invoice_hash(&stamped).unwrap()
        );
        // And any change to what the invoice says changes it.
        let mut other = sample();
        other.lines[0].name = "Setup and support".into();
        let changed = invoice_xml(&other, &Stamp::default()).unwrap();
        assert_ne!(
            invoice_hash(&changed).unwrap(),
            invoice_hash(&unstamped).unwrap()
        );
    }

    #[test]
    fn zatca_xml_chain_links_each_document_to_the_last() {
        let start = ChainState::default();
        let (icv, pih) = start.next();
        assert_eq!((icv, pih.as_str()), (1, FIRST_PIH));
        let after = start.advance(1, "h1".into()).unwrap();
        assert_eq!(after.next(), (2, "h1".to_owned()));
        assert!(after.advance(3, "h3".into()).is_err());
    }
}
