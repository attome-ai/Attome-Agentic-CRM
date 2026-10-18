//! Q18-T5: a decrypted secret that cannot be printed or serialised.
//!
//! [`SecretString`] has no `Display` and no `Serialize`, and its `Debug`
//! prints `[redacted]`, so a secret held in one cannot reach a log line, a
//! `{:?}` in an error, or a JSON response by accident. Reading it is an
//! explicit, greppable call: [`SecretString::expose_secret`] borrows it,
//! [`SecretString::into_exposed`] hands the `String` to a caller that needs
//! one (an HMAC key, a provider header). The buffer is zeroed on drop.

use std::fmt;

use zeroize::Zeroize;

/// A secret string: `Debug` prints `[redacted]`; no `Display`, no `Serialize`.
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Borrows the secret. Every read goes through here or
    /// [`Self::into_exposed`].
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Hands the secret over as a plain `String`, for a caller that must own
    /// it; the caller takes over the duty not to print it.
    pub fn into_exposed(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_redacted() {
        let secret = SecretString::new("hunter2".to_owned());
        assert_eq!(format!("{secret:?}"), "[redacted]");
        assert_eq!(format!("{:?}", Some(&secret)), "Some([redacted])");
        assert!(!format!("{secret:#?}").contains("hunter2"));
    }

    #[test]
    fn secret_reads_are_explicit() {
        let secret = SecretString::from("hunter2".to_owned());
        assert_eq!(secret.expose_secret(), "hunter2");
        assert_eq!(secret.into_exposed(), "hunter2");
    }
}
