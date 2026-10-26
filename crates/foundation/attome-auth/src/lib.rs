//! Authentication primitives and credential flows.
//!
//! This crate proves *who* a caller is. It does not decide what the caller
//! may do (authorization lives in `xrm-security`), it does not write the audit
//! trail (handlers emit audit events through `xrm-audit`; a `base-*` crate
//! cannot depend on an `xrm-*` crate), and it holds no HTTP routes (thin
//! handlers live in `crates/server/src/auth/` and `xrm-security`; the authn
//! middleware, category rate limiter and CSRF layer live in `attome-server`).
//!
//! # What lives here
//!
//! | Area | Modules |
//! |---|---|
//! | Session tokens | `jwt`, `session`, `revocation` (`jti` denylist), `epoch` (per-user kill switch), `auth_context` (sign-in time and methods) |
//! | Refresh tokens | `refresh` (rotating families, reuse detection) |
//! | Secrets at rest | `password` (Argon2id), `apikey_hash` (peppered HMAC), `envelope` (AES-256-GCM key rings) |
//! | Credential flows | `accounts`, `reset`, `verification`, `invitation`, `email_identity` |
//! | Second factor | `mfa` (TOTP, recovery codes, pending challenges), `otp` |
//! | Passkeys | `webauthn` (WebAuthn registration and assertion) |
//! | Step-up | `step_up` (sensitive-operation guard, single-use challenges, elevation) |
//! | Federation | `oidc` |
//! | Browser transport | `cookie` |
//!
//! # Security contract
//!
//! Changes to this crate, and to the call sites that enforce its results, are
//! reviewed against `document/base/auth/attome-auth-security-contract.md`: the
//! threat model, invariants I1–I17, the finding-to-test traceability matrix,
//! the dependency-failure contract, and the migration compatibility matrix.
//! The contract records which invariants hold today and which are still
//! pending an item of `document/base/auth/plans/attome-auth-plan.md` (the one
//! plan for this crate; it absorbed the former hardening plan and fourteen
//! others, and §12 resolves every old ID they are cited by).
//! Never describe a pending invariant as guaranteed.
//!
//! Rules that apply to every change here, independent of plan progress:
//!
//! - A Redis or database failure on a revocation, epoch, MFA-challenge,
//!   throttle or single-use-state check rejects the request (contract §6).
//! - Credential-bearing values — passwords, JWTs, bearer tokens, ID tokens,
//!   MFA secrets and codes, API keys, peppers, cookie values — are never
//!   logged, formatted into an error, or used as a metric label.
//! - Password hashing and verification stay inside `password`; this is the
//!   only crate that depends on `argon2`.
//! - A platform-generated secret is not a password: read D-112, D-317 and
//!   contract I4 before choosing how a new token table hashes its secrets.
//! - An authentication attempt invokes exactly one verifier, selected by the
//!   input contract; a failed credential type never falls through to another
//!   (contract I11).
//!
//! # Sanctioned XRM-table SQL (BAU-29, OD-10)
//!
//! This is a `base-*` crate, yet its credential flows read and write two
//! XRM-owned tables directly: `user_account` (password hash, account
//! state, `auth_epoch`, `last_login`, `google_sub`, `email_verified`) and
//! `user_identity` (federated links, read by step-up). That is a
//! sanctioned exception, not drift: every such statement touches credential
//! state that must commit in the same transaction as the token or elevation
//! it guards, and an `AccountStore` seam in `xrm-security` would move the SQL
//! without changing any behaviour. No new XRM table may be added to this list
//! without a ruling; attome-server's no-XRM-SQL guard (BSV-C3.9) carries these
//! statements as its permanent baseline.

pub mod accounts;
pub mod apikey_hash;
pub mod auth_context;
pub mod captcha;
pub mod cookie;
pub mod email_identity;
pub mod encrypted_columns;
pub mod envelope;
pub mod epoch;
pub mod invitation;
pub mod jwt;
/// Q18-T4: the rewrap job for every registered encrypted column.
pub mod key_rewrap;
pub mod mfa;
/// S11-T3: certificate-bound access tokens (RFC 8705).
pub mod mtls;
/// S11-T1: the OAuth client credentials token endpoint's core.
pub mod oauth_token;
pub mod oidc;
/// Q2-T1: identity provider presets, brokers included.
pub mod oidc_presets;
pub mod otp;
pub mod password;
/// Q7-T1: breached and reused passwords.
pub mod password_policy;
/// Q20-T3 — self-hosted proof-of-work challenge.
pub mod pow;
/// Z4-T2: principal kinds and the token type each carries.
pub mod principal;
pub mod refresh;
pub mod reset;
pub mod revocation;
pub mod session;
/// K5-T2: short signed links (preview links) with an expiry.
pub mod signed_link;
pub mod step_up;
pub mod verification;
/// Z4-T6: passkey (WebAuthn) registration and assertion.
pub mod webauthn;

pub use apikey_hash::{PepperRing, VerifyOutcome, dummy_hmac_hash, verify_api_key_secret};
pub use jwt::{create_token, validate_session_token, validate_token};
pub use password::{NewPassword, hash_password_async, verify_password_async};
pub use session::{SessionClaims, SessionId, TokenType};

/// Advisory-lock namespace for every key taken under the `"attome-auth/…"`
/// prefix (guidelines §2's `"{crate}/{operation}:{resource}"` convention) —
/// `email_identity::try_lock_email`'s `"attome-auth/account-email:{email}"` and
/// the secret-rewrap lock `"attome-auth/rewrap:{domain}"`, the latter taken from
/// `xrm-server`'s trigger handler and `crates/server`'s rewrap job rather than
/// from here, which is exactly why the constant is public.
///
/// Bound as the first argument of the two-argument
/// `pg_try_advisory_xact_lock($1, hashtext($2))` so a `hashtext` collision
/// between two unrelated keys can only happen *within* this subsystem, never
/// across subsystems (L-1 / TODO-027). The workspace-wide assignment table,
/// and the test that proves the ids stay distinct, live in
/// `crates/server/tests/advisory_lock_namespaces.rs`. Never reuse or renumber
/// an id.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 2;
