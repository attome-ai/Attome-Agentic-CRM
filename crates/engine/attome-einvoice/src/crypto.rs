//! Device keys and CSID secrets at rest: envelope-encrypted under
//! `einvoice.key_encryption_key`, its own trust domain (D-069): never the
//! integration, S2S or webhook keys. The same versioned wire format every
//! other secret column uses (`attome_auth::envelope`).

use attome_config::KeyRing;
use attome_types::AppError;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

const FIELD_NAME: &str = "einvoice.key_encryption_key";

/// A device key's PKCS#8 DER, encrypted for storage (base64 text).
pub fn encrypt_key(ring: &KeyRing, pkcs8_der: &[u8]) -> Result<String, AppError> {
    let sealed = attome_auth::envelope::encrypt_bytes(FIELD_NAME, ring, pkcs8_der)?;
    Ok(STANDARD.encode(sealed))
}

/// The stored key's PKCS#8 DER. Zeroed on drop.
pub fn decrypt_key(ring: &KeyRing, stored: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, AppError> {
    let sealed = STANDARD
        .decode(stored)
        .map_err(|_| AppError::internal("a stored device key is not valid base64"))?;
    Ok(zeroize::Zeroizing::new(
        attome_auth::envelope::decrypt_bytes(FIELD_NAME, ring, &sealed)?,
    ))
}

/// A CSID secret, encrypted for storage.
pub fn encrypt_secret(ring: &KeyRing, secret: &str) -> Result<String, AppError> {
    attome_auth::envelope::encrypt(FIELD_NAME, ring, secret)
}

/// A stored CSID secret.
pub fn decrypt_secret(ring: &KeyRing, stored: &str) -> Result<String, AppError> {
    attome_auth::envelope::decrypt(FIELD_NAME, ring, stored)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zatca::sign::DeviceKey;

    #[test]
    fn zatca_sign_device_keys_round_trip_encrypted_and_refuse_another_ring() {
        let ring = KeyRing::single("11".repeat(32));
        let key = DeviceKey::generate();
        let stored = encrypt_key(&ring, &key.to_pkcs8_der().unwrap()).unwrap();
        let back = DeviceKey::from_pkcs8_der(&decrypt_key(&ring, &stored).unwrap()).unwrap();
        assert_eq!(
            back.public_key_der().unwrap(),
            key.public_key_der().unwrap()
        );
        assert!(decrypt_key(&KeyRing::single("22".repeat(32)), &stored).is_err());
    }
}
