// Error mapping for the platform's established `AppError` / JSON error
// contract (attome-types/src/error.rs::IntoResponse, coding-guidelines.md
// §6/§12). Every code below is a literal copy of that `match` arm's second
// tuple element — keep this list in sync if a variant is ever added there.
export type ApiErrorKind =
  | 'not_found'
  | 'unauthorized'
  | 'forbidden'
  | 'conflict'
  | 'version_conflict'
  | 'idempotency_conflict'
  | 'validation_error'
  // D-472 / BTY-3: a rule violation carries the offending rule's id in the
  // body's `rule_id`, so a caller can name the rule it broke.
  | 'rule_violation'
  // D-789 §3.5: a business rule locks a field the write changed, or a locked
  // required field was left empty.
  | 'field_locked'
  | 'field_locked_required'
  | 'feature_unavailable'
  | 'feature_hidden'
  | 'rate_limit_exceeded'
  | 'overloaded'
  | 'capability_unavailable'
  | 'metadata_authoring_locked'
  | 'transition_not_allowed'
  | 'server_timeout'
  | 'payload_too_large'
  | 'idempotency_outcome_unknown'
  | 'idempotency_replay_unavailable'
  | 'reauth_required'
  // attome-server A5: the path exists but not for this method (the response
  // carries `Allow`).
  | 'method_not_allowed'
  | 'internal_error'
  // Not a real server code — this SDK's own fallback when `error` is missing,
  // unparseable, or a code newer than this SDK knows about.
  | 'unknown_error';

const KNOWN_KINDS: ReadonlySet<string> = new Set<ApiErrorKind>([
  'not_found',
  'unauthorized',
  'forbidden',
  'conflict',
  'version_conflict',
  'idempotency_conflict',
  'validation_error',
  'rule_violation',
  'field_locked',
  'field_locked_required',
  'feature_unavailable',
  'feature_hidden',
  'rate_limit_exceeded',
  'overloaded',
  'capability_unavailable',
  'metadata_authoring_locked',
  'transition_not_allowed',
  'server_timeout',
  'payload_too_large',
  'idempotency_outcome_unknown',
  'idempotency_replay_unavailable',
  'reauth_required',
  'method_not_allowed',
  'internal_error',
]);

/** Shape of the body `AppError::into_response` writes:
 * `{ "error": "<stable code>", "message": "<human text>", "request_id": "<uuid>" }`
 * (`request_id` is injected by `attome_server`'s `attach_request_id_to_error_body`
 * middleware, D-043 — absent only if that middleware somehow didn't run). */
export interface ApiErrorBody {
  error?: unknown;
  message?: unknown;
  request_id?: unknown;
  /** D-472 / BTY-3: the rule's id, on a `rule_violation` 422. */
  rule_id?: unknown;
}

/** Thrown by every `AttomeTransport`/`AttomeClient` call for a non-2xx
 * response. Carries the server's stable `code` (and a typed `kind` for the
 * codes this SDK knows about) rather than a generic "HTTP error" — match on
 * `kind` (or `status`) instead of parsing `message`, which is human text and
 * not a stable contract. */
export class ApiError extends Error {
  /** HTTP status code. */
  readonly status: number;
  /** Typed classification of `code` — `'unknown_error'` for anything this
   * SDK version doesn't recognise (still usable via `code`/`status`). */
  readonly kind: ApiErrorKind;
  /** The server's raw `error` field, verbatim. Equal to `kind` for every
   * known code; the source of truth when `kind` is `'unknown_error'`. */
  readonly code: string;
  /** Correlates with the server's request-scoped logs (`x-request-id`). */
  readonly requestId?: string;
  /** The full parsed response body, for anything not covered above. */
  readonly body: unknown;

  constructor(
    status: number,
    kind: ApiErrorKind,
    code: string,
    message: string,
    requestId: string | undefined,
    body: unknown,
  ) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.kind = kind;
    this.code = code;
    this.requestId = requestId;
    this.body = body;
  }

  /** Best-effort "is a retry after backoff reasonable" signal. Never true for
   * a 4xx (client-error) response — those need the request changed, not
   * retried as-is. */
  get isRetryable(): boolean {
    return this.status >= 500 || this.kind === 'rate_limit_exceeded';
  }
}

/** The step-up details a `reauth_required` 401 carries (D-510 rule 6). */
export interface ReauthDetails {
  /** The protected operation, e.g. `identity_link` or `api_key_create`. */
  operation: string;
  /** `totp`, `recovery_code`, `password`, `federated`, or the single
   * `totp_enrollment_required` when no step-up challenge can help. */
  acceptableFactors: string[];
}

/** Typed access to a `reauth_required` error's `operation` and
 * `acceptable_factors`. `null` for any other error, or when the body lacks a
 * string `operation`. Such a 401 is never an expired session: step up on the
 * same session and retry, do not refresh or sign out. API-key and S2S callers
 * never see it — they get 403 on these operations. */
export function reauthDetails(err: ApiError): ReauthDetails | null {
  if (err.kind !== 'reauth_required') return null;
  const b = err.body && typeof err.body === 'object' ? (err.body as Record<string, unknown>) : {};
  if (typeof b['operation'] !== 'string') return null;
  const factors = Array.isArray(b['acceptable_factors'])
    ? b['acceptable_factors'].filter((f): f is string => typeof f === 'string')
    : [];
  return { operation: b['operation'], acceptableFactors: factors };
}

/** Builds an `ApiError` from a parsed (or unparseable) response body. Never
 * throws itself — a malformed/non-JSON error body still yields a usable
 * `ApiError` rather than losing the original HTTP status. */
export function mapErrorResponse(status: number, requestIdHeader: string | null, body: unknown): ApiError {
  const b: ApiErrorBody = body && typeof body === 'object' ? (body as ApiErrorBody) : {};
  const code = typeof b.error === 'string' && b.error.length > 0 ? b.error : `http_${status}`;
  const message =
    typeof b.message === 'string' && b.message.length > 0 ? b.message : `request failed with status ${status}`;
  const requestId = typeof b.request_id === 'string' ? b.request_id : (requestIdHeader ?? undefined);
  const kind = (KNOWN_KINDS.has(code) ? code : 'unknown_error') as ApiErrorKind;
  return new ApiError(status, kind, code, message, requestId, body);
}
