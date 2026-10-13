import { inject, Injectable } from '@angular/core';
import { HttpClient, HttpErrorResponse, HttpHeaders, HttpParams, HttpResponse } from '@angular/common/http';
import { Observable, catchError, throwError } from 'rxjs';
import { ATTOME_CONFIG, ApiService, CHANGESET_HEADER } from '@attome/base';
import type { ApiError, ApiErrorKind } from '@attome/base';

/**
 * Solution 7 Phase 2 (D-788, D-791) — the stable refusal codes the release
 * report, the recovery archive and the field-change routes answer with.
 *
 * On the wire most of them are a plain `409 conflict` whose message reads
 * `conflict: <code>: <prose>` (or a `422 validation_error` whose message
 * starts with `<code>:`); a blocked field change is a `409` whose body is the
 * whole `FieldChangeResult` with the code in `error`. `stableErrorCode` finds
 * the code in either shape so the screen can say what happened in the user's
 * language.
 */
export const STABLE_ERROR_CODES = [
  // Release report (`attome_api::admin::release_report`, `attome_core::release_report`).
  'report_item_decided',
  'report_item_kind',
  'report_values_missing',
  'report_values_unreadable',
  'record_field_missing',
  // Recovery archive (`attome_api::admin::recovery_archive`, `attome_core::recovery_archive`).
  'archive_key_missing',
  'archive_expired',
  'archive_value_unreadable',
  'restore_target_missing',
  'restore_not_convertible',
  // Field changes (`attome_api::field_changes`, `attome_metadata::provision::field_change`).
  'rename_blocked_by_reference',
  'rename_target_exists',
  'rename_conflicts_open_changeset',
  'field_busy',
  'field_referenced',
  'field_in_use',
  'field_in_business_key',
  'field_not_found',
  'type_drift',
  'conversion_not_defined',
  'column_budget',
  'choice_value_reserved',
  'run_not_failed',
  // Solution 7 changeset refusals (`attome_core::changeset::errors`).
  'changeset_required',
  'changeset_ambiguous',
  'changeset_not_open',
  'layer_mismatch',
  // Optimistic concurrency (`AppError::VersionConflict`).
  'version_conflict',
] as const;
export type StableErrorCode = typeof STABLE_ERROR_CODES[number];

/** An `ApiError` that also keeps the response body (a blocked change's result). */
export interface AdminApiError extends ApiError {
  /** The parsed JSON body, when there was one. */
  body?: unknown;
}

function isStable(code: unknown): code is StableErrorCode {
  return typeof code === 'string' && (STABLE_ERROR_CODES as readonly string[]).includes(code);
}

/**
 * The stable code behind a failed call, or `null`. Looks at, in order: a
 * `version_conflict` kind, the `error` code (a blocked change's body carries
 * its refusal there), and the `<code>:` prefix inside the server's message.
 */
export function stableErrorCode(
  err: Pick<ApiError, 'kind' | 'code' | 'message'> | null | undefined,
): StableErrorCode | null {
  if (!err) return null;
  if (err.kind === 'version_conflict' || err.code === 'version_conflict') return 'version_conflict';
  if (isStable(err.code)) return err.code;
  const message = typeof err.message === 'string' ? err.message : '';
  for (const code of STABLE_ERROR_CODES) {
    if (message.startsWith(`${code}:`) || message.includes(` ${code}:`) || message === code) return code;
  }
  return null;
}

/** Mirrors `AppError::into_response`'s codes for the kinds these screens branch on. */
function kindOf(code: unknown, status: number): ApiErrorKind {
  switch (code) {
    case 'version_conflict': return 'version_conflict';
    case 'conflict':         return 'conflict';
    case 'validation_error': return 'validation';
    case 'not_found':        return 'not_found';
    case 'forbidden':        return 'forbidden';
    case 'unauthorized':     return 'unauthorized';
    case 'internal_error':   return 'internal';
    case 'metadata_authoring_locked':      return 'authoring_locked';
    case 'reauth_required':                return 'reauth_required';
    case 'rate_limit_exceeded':            return 'rate_limited';
    case 'feature_hidden':                 return 'feature_hidden';
    case 'payload_too_large':              return 'payload_too_large';
    case 'idempotency_conflict':           return 'idempotency_conflict';
    case 'idempotency_outcome_unknown':    return 'idempotency_outcome_unknown';
    case 'idempotency_replay_unavailable': return 'idempotency_replay_unavailable';
    case 'feature_unavailable':
    case 'capability_unavailable':
    case 'overloaded':
    case 'server_timeout':                 return 'unavailable';
  }
  switch (status) {
    case 401: return 'unauthorized';
    case 403: return 'forbidden';
    case 404: return 'not_found';
    case 409: return 'conflict';
    case 422: return 'validation';
    case 500: return 'internal';
    case 503: return 'unavailable';
    default:  return 'unknown';
  }
}

/** `HttpErrorResponse` → `AdminApiError`, keeping the body. */
export function toAdminApiError(err: HttpErrorResponse): AdminApiError {
  const body: unknown = err.error;
  const obj = body && typeof body === 'object' ? body as Record<string, unknown> : {};
  const error: AdminApiError = {
    status:  err.status,
    kind:    kindOf(obj['error'], err.status),
    message: typeof obj['message'] === 'string' ? obj['message'] : '',
    body,
  };
  if (typeof obj['error'] === 'string') error.code = obj['error'];
  if (typeof obj['request_id'] === 'string') error.requestId = obj['request_id'];
  return error;
}

export interface AdminRequestOptions {
  body?: unknown;
  /** Sent as `If-Match: "<n>"` (a release-report item's `row_version`). */
  ifMatch?: number;
  params?: Record<string, string>;
}

/**
 * The few admin writes `ApiService` cannot express: a `POST` that needs
 * `If-Match` (the release-report decisions), and a write whose `409`/`202`
 * body the screen must read (a blocked field change lists its blockers; a
 * large table answers `202` with a `run_id`). Same URL base, credentials and
 * changeset header as `ApiService`; the auth interceptor still adds CSRF.
 *
 * TODO(api-service): fold into `ApiService` once it can send `If-Match` on a
 * POST and hand back a refused write's body.
 */
@Injectable({ providedIn: 'root' })
export class AdminHttp {
  private readonly http   = inject(HttpClient);
  private readonly config = inject(ATTOME_CONFIG);
  private readonly api    = inject(ApiService);

  request<T>(method: 'POST' | 'DELETE', path: string, options: AdminRequestOptions = {}): Observable<HttpResponse<T>> {
    let headers = new HttpHeaders();
    if (options.ifMatch !== undefined) headers = headers.set('If-Match', `"${options.ifMatch}"`);
    const changeset = this.api.activeChangeset();
    if (changeset) headers = headers.set(CHANGESET_HEADER, changeset);
    let params = new HttpParams();
    for (const [k, v] of Object.entries(options.params ?? {})) params = params.set(k, v);
    return this.http.request<T>(method, `${this.config.apiUrl}${path}`, {
      body: options.body,
      headers,
      params,
      observe: 'response',
      withCredentials: true,
    }).pipe(catchError((err: HttpErrorResponse) => throwError(() => toAdminApiError(err))));
  }
}
