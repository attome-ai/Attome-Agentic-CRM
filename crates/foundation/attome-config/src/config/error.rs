use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config file not found at '{path}': {error}")]
    FileNotFound { path: String, error: String },

    #[error(
        "config path '{path}' is a directory, not a file — Docker creates an empty directory at \
         a bind-mount target whose host-side file does not exist yet; remove it, create the file \
         (from config.production.example.json), and start again"
    )]
    NotAFile { path: String },

    #[error("failed to parse config file '{path}': {error}")]
    Parse { path: String, error: String },

    #[error("insecure config value for '{field}': {reason}")]
    Insecure { field: String, reason: String },

    /// BCF-11 — a value that is out of range, malformed, or not one of the
    /// allowed variants. Distinguished from `ConfigError::Insecure` so triage
    /// knows whether the operator typed something wrong (fix the value) or
    /// declared an unsafe posture (fix the policy).
    #[error("invalid config value for '{field}': {reason}")]
    Invalid { field: String, reason: String },

    #[error(
        "unresolved ${{...}} placeholders in '{path}': {keys} — set the environment variables \
         or remove the entries (only APP_ENV=debug tolerates unresolved placeholders)"
    )]
    UnresolvedPlaceholders { path: String, keys: String },

    #[error("config file '{path}' still has '{field}': {hint}")]
    DeprecatedField {
        path: String,
        field: String,
        hint: String,
    },
}
