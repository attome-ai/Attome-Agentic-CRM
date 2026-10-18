//! AG2 — e-invoicing (ZATCA Fatoora phase 2 first). Ships dark
//! (`enabled: false`): a deployment that invoices in Saudi Arabia turns it on
//! and onboards its devices.
//!
//! `key_encryption_key` is its own [`KeyRing`], separate from every other
//! trust domain in this config (D-069): it encrypts the devices' ECDSA
//! signing keys at rest (`attome_einvoice::crypto`) and nothing else. A
//! rotation or compromise of another ring never implicates these keys.
use crate::keyring::KeyRing;
use serde::Deserialize;

/// Hand-written so the key ring prints the way every other ring does (BCF-1).
impl std::fmt::Debug for EinvoiceSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EinvoiceSection")
            .field("enabled", &self.enabled)
            .field("key_encryption_key", &self.key_encryption_key)
            .finish()
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct EinvoiceSection {
    pub enabled: bool,
    pub key_encryption_key: KeyRing,
}
