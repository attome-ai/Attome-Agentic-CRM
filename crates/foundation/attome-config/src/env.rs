//! The one reading of `APP_ENV` (cleanup 3.7).
//!
//! `APP_ENV=debug` marks a local development process: it selects
//! `config.debug.json`, tolerates unresolved `${VAR}`s and a missing
//! `database.runtime`/`database.migrator` split, and unlocks the dev-only
//! seeds and test namespaces. Every "is this the debug environment?" check
//! goes through here, so the variable name and the `"debug"` literal live in
//! one place.

/// The environment variable that names the process's environment.
pub const APP_ENV_VAR: &str = "APP_ENV";

/// The `APP_ENV` value that marks a local development process.
pub const DEBUG_APP_ENV: &str = "debug";

/// The raw `APP_ENV` value, `None` when unset or not valid Unicode. For a
/// caller that injects the value into a pure, unit-testable decision (pair it
/// with [`is_debug_app_env`]).
pub fn app_env() -> Option<String> {
    std::env::var(APP_ENV_VAR).ok()
}

/// Whether an injected `APP_ENV` value is the debug environment.
pub fn is_debug_app_env(app_env: Option<&str>) -> bool {
    app_env == Some(DEBUG_APP_ENV)
}

/// Whether this process runs with `APP_ENV=debug`. Exact and case-sensitive:
/// `Debug`, ` debug` or an unset variable are all "not debug", so anything
/// short of the exact value keeps the stricter production behaviour.
pub fn is_debug_env() -> bool {
    is_debug_app_env(app_env().as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_exact_value_is_debug() {
        assert!(is_debug_app_env(Some("debug")));
        for other in [
            None,
            Some(""),
            Some("Debug"),
            Some(" debug"),
            Some("production"),
        ] {
            assert!(!is_debug_app_env(other), "{other:?}");
        }
    }
}
