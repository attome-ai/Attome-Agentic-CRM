//! `attome-types`: the platform-wide vocabulary, the shared response and
//! error shapes every other crate builds on. It is the bottom of the
//! foundation layer: it has no internal dependencies, and nothing here should
//! ever need one. Its external dependencies are limited to the serde, utoipa,
//! axum, tracing and opentelemetry facades.
//!
//! **Allowed:** shared response envelopes (`PaginatedResponse`,
//! `CursorPage`), the platform error vocabulary (`AppError`,
//! `ErrorResponse`), dependency-free primitive helpers (`text::
//! normalize_email`), and tracing/header primitives (`w3c_trace`'s
//! `traceparent` format/parse).
//!
//! **Forbidden:** database types (no `sqlx`), authentication/authorization
//! logic, CRM entity or other business-domain types, service-specific DTOs,
//! and infrastructure clients (HTTP, Redis, S3, email). If a proposed
//! addition needs one of those, it belongs in a higher layer, not here.
//!
//! **Why `AppError` implements Axum's `IntoResponse` despite living in the
//! foundation layer:** it is the canonical application-boundary error
//! contract, intentionally HTTP-aware because every application HTTP
//! boundary in this platform terminates in Axum — it is not a
//! general-purpose library error type. Infrastructure errors are translated
//! into it by their *owning* layer before it ever sees them, not the other
//! way around: `attome_db::classify` is the concrete example —
//! `sqlx::Error` → `AppError` classification lives there, keeping `sqlx`
//! itself out of this crate. Treat that split as deliberate, not an
//! oversight to "fix" by pulling infrastructure error types down here.

/// Z15-T5: the time a decision reads (a fake one in tests).
pub mod clock;
pub mod error;
pub mod error_codes;
pub mod request_scope;
pub mod text;
pub mod types;
pub mod w3c_trace;

pub use clock::{Clock, FakeClock, SystemClock};
pub use error::AppError;
pub use types::*;
