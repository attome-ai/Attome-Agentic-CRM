//! The engine's typed errors, mapped onto the HTTP error contract.
use attome_types::AppError;

#[derive(Debug, thiserror::Error)]
pub enum OpsError {
    #[error("not found")]
    NotFound,
    #[error("forbidden")]
    Forbidden,
    #[error("conflict: {0}")]
    Conflict(&'static str),
    #[error("{0}")]
    Validation(String),
    /// A dependency the operation needs (a Patroni node, the drill key) is
    /// not there; named for logs, never shown to the client.
    #[error("unavailable: {0}")]
    Unavailable(&'static str),
    #[error("internal: {0}")]
    Internal(String),
}

impl From<OpsError> for AppError {
    fn from(e: OpsError) -> Self {
        match e {
            OpsError::NotFound => AppError::NotFound,
            OpsError::Forbidden => AppError::Forbidden,
            OpsError::Conflict(what) => AppError::Conflict(what),
            OpsError::Validation(message) => AppError::Validation(message),
            OpsError::Unavailable(what) => AppError::CapabilityUnavailable(what),
            OpsError::Internal(message) => AppError::internal(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_errors_map_to_the_http_contract() {
        assert!(matches!(
            AppError::from(OpsError::NotFound),
            AppError::NotFound
        ));
        assert!(matches!(
            AppError::from(OpsError::Conflict("a switchover is running")),
            AppError::Conflict("a switchover is running")
        ));
        assert!(matches!(
            AppError::from(OpsError::Unavailable("patroni")),
            AppError::CapabilityUnavailable("patroni")
        ));
        assert!(matches!(
            AppError::from(OpsError::Validation("bad".into())),
            AppError::Validation(_)
        ));
    }
}
