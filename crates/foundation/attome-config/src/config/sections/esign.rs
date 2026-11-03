//! K4-T2 — e-signature sealing. Both files empty (the default) leaves
//! completed envelopes unsealed; set both and every completed envelope's PDFs
//! get a PAdES seal under the deployment's signing certificate
//! (`attome_document::esign_seal`).
use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct EsignSection {
    /// Path to the PEM certificate chain the seal is made with, the signing
    /// certificate first (RSA or P-256). Empty: completed envelopes are not
    /// sealed.
    pub seal_certificate_file: String,
    /// Path to the signing certificate's private key, PEM (PKCS #8, or
    /// PKCS #1 for RSA). Read when a seal is made; keep the file readable by
    /// the server only.
    pub seal_key_file: String,
}
