import type { components } from './generated/api-types';

// ── Mirrors Rust's AppError variants ─────────────────────────────────────────

/**
 * NGB-2.1. One member per `AppError` wire code
 * (`crates/foundation/attome-types/src/error.rs::into_response`), plus `unknown` for a
 * status the body does not explain. Codes that share a status stay distinct
 * (`conflict` vs `version_conflict` vs `idempotency_conflict` — all 409), and
 * transient/licensing 503s collapse into `unavailable` because the UI's
 * answer is the same for every one of them.
 */
export type ApiErrorKind =
  | 'validation'
  | 'not_found'
  | 'unauthorized'
  | 'forbidden'
  | 'conflict'
  | 'version_conflict'
  | 'internal'
  // D-510 rule 6: a sensitive operation needs a fresh step-up on this session.
  // Never an expired session — see `authInterceptor` and `StepUpService`.
  | 'reauth_required'
  // ── NGB-2.1 additions ──────────────────────────────────────────────────────
  /** `rate_limit_exceeded` (429) — back off and retry. */
  | 'rate_limited'
  /**
   * `feature_unavailable` / `capability_unavailable` / `overloaded` /
   * `server_timeout` (all 503). The three differ only in the operator's
   * remedy (off, dependency down, shedding load) and none of them is
   * actionable by the person in front of the screen.
   */
  | 'unavailable'
  /** `payload_too_large` (413). */
  | 'payload_too_large'
  /** `feature_hidden` (403) — the licensed module is not in this deployment. */
  | 'feature_hidden'
  /** `idempotency_conflict` (409) — the key was reused for a different request. */
  | 'idempotency_conflict'
  /** `idempotency_outcome_unknown` (409) — do not blind-retry. */
  | 'idempotency_outcome_unknown'
  /** `idempotency_replay_unavailable` (409) — the write happened; the response is gone. */
  | 'idempotency_replay_unavailable'
  /** `rule_violation` (422) — a business rule refused the write; see `ruleId`. */
  | 'rule_violation'
  /** `transition_not_allowed` (422) — no configured state transition for this change. */
  | 'transition_not_allowed'
  /** `metadata_authoring_locked` (403) — the production profile forbids authoring. */
  | 'authoring_locked'
  | 'unknown';

export interface ApiError {
  kind:    ApiErrorKind;
  /**
   * NGB-2.3: the server's own text, and **only** meaningful for `validation`
   * and `rule_violation` — a field name, or which rule refused the write.
   * `ApiService` leaves this empty when the body carries none, so a caller
   * must render `LangService.errorText(err)` rather than this directly;
   * the server answers in English and the UI may not be.
   */
  message: string;
  status:  number;
  /**
   * The server's raw `error` code, when the body carried one — except a
   * Solution 7 changeset refusal (`changeset_required`, `layer_mismatch`, …),
   * which is a plain `conflict` on the wire and carries its stable code as the
   * message prefix; `ApiService` puts that code here instead (`kind` stays
   * `conflict`).
   */
  code?:   string;
  /**
   * NGB-2.1: lets support match a UI error to the server's logs. Read from the
   * body's `request_id`, else the `x-request-id` response header (which needs
   * a CORS `expose_headers` entry to be visible cross-origin — attome-server
   * BSV-A2).
   */
  requestId?: string;
  /**
   * `rule_violation` (M45 Phase 2 / D-472) and `field_locked` /
   * `field_locked_required` (D-789): which rule refused the write.
   */
  ruleId?: string;
  /**
   * D-789: the field a refusal names, from the body's top-level `field`
   * (`field_locked`, `field_locked_required`: the first locked field).
   */
  field?: string;
  /** D-789: the body's `rule_name` (`field_locked*`) — the rule's display name. */
  ruleName?: string;
  /** D-789: the body's `effect` (`field_locked*`) — `hidden` or `disabled`. */
  effect?: string;
  /**
   * The body's `details`, unchanged, when it carries one. Its shape depends on
   * the code (`ErrorResponse.details` in `attome-types`): a `FieldError[]` on
   * `validation_error`, `{field?, rules}` on `rule_violation`, `{fields:
   * LockedField[]}` on `field_locked*`. Untyped here; the consumer narrows.
   */
  details?: unknown;
  /** `reauth_required` only: the protected operation (`identity_link`, `api_key_create`). */
  operation?: string;
  /**
   * `reauth_required` only: the factors a step-up accepts now (`password`,
   * `totp`, `recovery_code`, `federated`), or the single
   * `totp_enrollment_required` when no challenge can help.
   */
  acceptableFactors?: string[];
}

// ── Step-up (D-510) and self-service API keys ────────────────────────────────

/** `GET /api/v1/auth/step-up/{operation}`. */
export type StepUpStatus = components['schemas']['StepUpStatusBody'];
/** `POST /api/v1/auth/step-up/{operation}` (201). */
export type StepUpChallenge = components['schemas']['StepUpChallengeBody'];
/** `POST /api/v1/auth/step-up/{operation}/verify` request body. */
export type StepUpVerifyRequest = components['schemas']['StepUpVerifyBody'];
/** `POST /api/v1/auth/step-up/{operation}/verify` (200). */
export type StepUpElevation = components['schemas']['StepUpElevationBody'];
/** `POST /api/v1/auth/api-keys` request body. */
export type CreateApiKeyRequest = components['schemas']['CreateApiKeyBody'];
/** `POST /api/v1/auth/api-keys` (201) — `secret` is returned exactly once. */
export type ApiKeyCreated = components['schemas']['ApiKeyCreated'];

// ── Auth ──────────────────────────────────────────────────────────────────────
//
// NGB-2.4: every one of these has a named schema in the generated document, so
// the wire shape is `components['schemas'][…]` — the compiler, not review,
// catches a backend rename. The two narrowed fields are narrowed for a reason;
// see their comments. `types.lockstep.spec.ts` fails if one of them is ever
// hand-written again, or if the backend publishes a schema for one of the six
// types at the bottom of this file that still has no named schema.

/** `GET /api/v1/auth/session` (D-129). */
export type SessionInfo = components['schemas']['SessionInfo'];

export interface AuthResponse { // no named schema yet (lockstep spec)
  user_id: string;
}

export type GoogleAuthRequest = components['schemas']['GoogleAuthRequest'];

export type RegisterRequest = components['schemas']['RegisterRequest'];

/**
 * P-registration-gating (D-128). The generated schema types `mode` as
 * `string` (its one-of lives in a doc comment), and the host app assigns it to
 * a `'public' | 'invite' | 'disabled'` signal — narrowing here keeps that
 * contract and the existing `=== 'invite'` branches honest.
 */
export type RegistrationConfigInfo =
  components['schemas']['RegistrationConfigInfo'] & { mode: 'public' | 'invite' | 'disabled' };

export type LoginRequest = components['schemas']['LoginRequest'];

/** P2.8 step 5 — one entry per `config.oidc.providers` key. */
export type OidcProviderInfo = components['schemas']['OidcProviderInfo'];

/**
 * P-federation-linking-policy §4.3(a) — `linked_at` is absent only for the
 * synthetic `provider_key: "google"` entry (Google links via
 * `core_systemuser.google_sub`, so it has no per-link timestamp).
 */
export type IdentityLinkInfo = components['schemas']['IdentityLinkInfo'];

/**
 * P-frontend-baseline step 5 — `client_id` is null when Google sign-in isn't
 * configured. The generated schema marks it optional (the OpenAPI document
 * cannot say "serde always emits `Option::None` as null"), and three host call
 * sites assign it straight to a `signal<string | null>`; requiring-nullable
 * here is both true of this server and keeps them compiling.
 */
export type GoogleConfigInfo =
  components['schemas']['GoogleConfigInfo'] & { client_id: string | null };

// ── Multi-factor authentication (P2.8 step 7, D-069) ───────────────────────────

/**
 * `POST /api/v1/auth/login`'s alternate response shape: a correct password
 * that still needs a second factor before a session exists. Distinguish from
 * `AuthResponse` with `isMfaChallenge`. No named schema yet (lockstep spec).
 */
export interface MfaChallenge {
  mfa:           'required' | 'enrollment_required';
  pending_token: string;
}

export function isMfaChallenge(res: AuthResponse | MfaChallenge): res is MfaChallenge {
  return (res as MfaChallenge).mfa !== undefined;
}

export type MfaVerifyBody = components['schemas']['MfaVerifyBody'];

export type MfaPendingEnrollBody = components['schemas']['MfaPendingEnrollBody'];

export interface MfaEnrollResponse { // no named schema yet (lockstep spec)
  secret_base32: string;
  otpauth_uri:   string;
}

export interface MfaPendingConfirmResponse { // no named schema yet (lockstep spec)
  user_id:        string;
  recovery_codes: string[];
}

/** Self-service `GET /api/v1/auth/mfa/status`. No named schema yet (lockstep spec). */
export interface MfaStatus {
  enrolled: boolean;
}

/** Self-service confirm/regenerate-recovery-codes shape. No named schema yet (lockstep spec). */
export interface MfaRecoveryCodes {
  recovery_codes: string[];
}

// ── Account lifecycle (P-account-lifecycle) ───────────────────────────────────

export type ResetRequestBody = components['schemas']['ResetRequestBody'];

export type ResetConfirmBody = components['schemas']['ResetConfirmBody'];

export type VerifyEmailConfirmBody = components['schemas']['VerifyEmailConfirmBody'];

/** Uniform ack shape shared by reset-request/reset-confirm/verify-email/confirm. */
export type Ack = components['schemas']['Ack'];

// ── Generic API list response ─────────────────────────────────────────────────

export interface ListMeta {
  total:  number;
  limit:  number;
  offset: number;
}

export interface ListResponse<T> {
  data: T[];
  meta: ListMeta;
}

// ── Session state ─────────────────────────────────────────────────────────────

export interface Session {
  userId:   string;
  loggedIn: boolean;
}
