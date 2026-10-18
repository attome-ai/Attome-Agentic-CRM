import { inject, Injectable, signal } from '@angular/core';
import { HttpClient, HttpErrorResponse, HttpParams } from '@angular/common/http';
import { EMPTY, Observable, catchError, defer, expand, map, of, reduce, throwError } from 'rxjs';
import { ATTOME_CONFIG } from './config';
import { ApiError } from './types';

/**
 * The `{items, total, page, page_size}` envelope every paginated admin-catalog
 * endpoint returns (`attome_types::PaginatedResponse<T>` on the wire, guidelines
 * §12) — exported (C-26) so a service typing a paginated response reuses this
 * instead of re-declaring the same four fields under a service-specific name
 * (`UserListPage`, etc.), the drift `entity.service.ts`'s doc comment already
 * warns about for hand-written wire types generally.
 */
/**
 * NGB-2.5 / OD-4b — the typed per-call option bag for a mutating request,
 * replacing the raw header bag `post` used to take.
 */
export interface WriteOptions {
  /**
   * Sent as `x-idempotency-key` (`attome_server::middleware::idempotency`). The
   * server replays the stored response for a repeat under the same key, which
   * is also what makes it safe for `authInterceptor` to retry a keyed
   * non-GET once after a refresh.
   */
  idempotencyKey?: string;
  /** A `row_version` sent as `If-Match` on a POST that guards one (a publish, say). */
  ifMatch?: number;
  /**
   * A18: sent as `Attome-Operation-Id`, grouping several deletes into one
   * operation the recycle bin can restore at once (the undo after a delete).
   */
  operationId?: string;
  /**
   * A15-T4: sent as `Attome-Duplicate-Reason` — why this save goes ahead
   * although it matches an existing record under an `allow_with_reason`
   * duplicate rule. The audit keeps it.
   */
  duplicateReason?: string;
}

/** `If-Match` from `etag`, plus the idempotency key. */
function writeHeaders(options: WriteOptions, etag?: number): Record<string, string> {
  const headers: Record<string, string> = {};
  if (options.idempotencyKey) headers['x-idempotency-key'] = options.idempotencyKey;
  if (etag !== undefined) headers['If-Match'] = `"${etag}"`;
  if (options.operationId) headers['Attome-Operation-Id'] = options.operationId;
  if (options.duplicateReason) headers['Attome-Duplicate-Reason'] = options.duplicateReason;
  return headers;
}

export interface Page<T> {
  items:     T[];
  total:     number;
  page:      number;
  page_size: number;
}

/**
 * Ceiling on how many records `ApiService.getAllPages` will walk (F-012).
 * Every current caller is an admin catalog — entities, views, stored queries,
 * roles, grants, teams, S2S clients — whose realistic size is hundreds; 10k is
 * far above any of them and still ~50 sequential requests, so crossing it means
 * the screen has outgrown "fetch everything" rather than that the limit is low.
 * `@attome/sdk`'s `MAX_ALL_PAGES_ITEMS` holds the same value; keep them equal.
 */
export const MAX_ALL_PAGES_ITEMS = 10_000;

/**
 * Never reaches the wire, hence `status: 0` — but it is shaped like every other
 * `ApiError` so a component's existing error branch renders it unchanged. Kind
 * `validation` because it is actionable by the caller (narrow the request), not
 * a server fault.
 *
 * NGB-3.3: no English here. `code` names the catalog entry
 * (`errors.too_many_pages`), which `LangService.errorText` resolves in the
 * active language; `total`/`maxItems` are still carried for a caller that
 * wants to log them (`logTooManyPages`).
 */
function tooManyPages(total: number, maxItems: number): ApiError {
  logTooManyPages(total, maxItems);
  return {
    status:  0,
    kind:    'validation',
    code:    'too_many_pages',
    message: '',
  };
}

/** The concrete numbers behind `errors.too_many_pages`, for the dev console. */
function logTooManyPages(total: number, maxItems: number): void {
  console.warn(`[attome] getAllPages stopped: ${total} records exceeds the ${maxItems}-item ceiling.`);
}

/**
 * Solution 7 (D-785) — names the open changeset a metadata admin write records
 * into (`attome_core::changeset::extract::CHANGESET_HEADER`). Sent only on
 * mutating requests: the recorder reads it on writes, and a GET carrying it
 * would buy a CORS preflight for nothing.
 */
export const CHANGESET_HEADER = 'X-Attome-Changeset';

/**
 * The stable codes a changeset refusal's message starts with
 * (`attome_core::changeset::errors`, `HARD_DELETE_NOT_RECORDABLE`). Until
 * `AppError` gains a variant carrying them, each one reaches the wire as a
 * `409 conflict` whose message reads `conflict: <code>: <prose>`; `ApiService`
 * lifts the code into `ApiError.code` so `LangService.errorText` renders the
 * catalog's `errors.<code>` rather than the generic "someone else changed this".
 */
export const CHANGESET_REFUSAL_CODES = [
  'changeset_required',
  'changeset_ambiguous',
  'changeset_not_open',
  'layer_mismatch',
  'hard_delete_not_recordable',
] as const;
export type ChangesetRefusalCode = typeof CHANGESET_REFUSAL_CODES[number];

/** The refusal code a `409 conflict` message starts with, or `null`. */
export function changesetRefusalCode(message: unknown): ChangesetRefusalCode | null {
  if (typeof message !== 'string') return null;
  const rest = message.startsWith('conflict: ') ? message.slice('conflict: '.length) : message;
  const code = rest.split(':', 1)[0].trim();
  return (CHANGESET_REFUSAL_CODES as readonly string[]).includes(code)
    ? code as ChangesetRefusalCode
    : null;
}

/** `conflict: layer_mismatch: this object is …` → `This object is …`. */
function refusalProse(message: string, code: ChangesetRefusalCode): string {
  const at = message.indexOf(`${code}:`);
  const prose = at >= 0 ? message.slice(at + code.length + 1).trim() : message;
  return prose ? prose.charAt(0).toUpperCase() + prose.slice(1) : message;
}

@Injectable({ providedIn: 'root' })
export class ApiService {
  private readonly http   = inject(HttpClient);
  private readonly config = inject(ATTOME_CONFIG);

  /**
   * Solution 7 (D-785): the changeset id every mutating request names through
   * `X-Attome-Changeset`, or `null` to send none (the server then uses the
   * caller's single open changeset, or refuses/auto-records per its mode).
   * Set only through `setChangeset` — nothing here picks one implicitly.
   */
  private readonly changesetId = signal<string | null>(null);
  readonly activeChangeset = this.changesetId.asReadonly();

  /**
   * Names the changeset later mutating requests record into; `null` clears
   * it. An empty or whitespace-only id is treated as `null` so a blank picker
   * never sends a header the server would reject as malformed (422).
   */
  setChangeset(id: string | null): void {
    const trimmed = id?.trim() ?? '';
    this.changesetId.set(trimmed.length > 0 ? trimmed : null);
  }

  private url(path: string): string {
    return `${this.config.apiUrl}${path}`;
  }

  /** `writeHeaders` plus the picked changeset, when there is one. */
  private mutationHeaders(options: WriteOptions, etag?: number): Record<string, string> {
    const headers = writeHeaders(options, etag);
    const changeset = this.changesetId();
    if (changeset && !Object.keys(headers).some(k => k.toLowerCase() === CHANGESET_HEADER.toLowerCase())) {
      headers[CHANGESET_HEADER] = changeset;
    }
    return headers;
  }

  get<T>(path: string, params?: Record<string, string | string[]>): Observable<T> {
    let httpParams = new HttpParams();
    if (params) {
      for (const [key, val] of Object.entries(params)) {
        if (Array.isArray(val)) val.forEach(v => httpParams = httpParams.append(key, v));
        else httpParams = httpParams.set(key, val);
      }
    }
    return this.http.get<T>(this.url(path), { params: httpParams, withCredentials: true })
      .pipe(catchError(this.handleError));
  }

  /**
   * A conditional GET: sends `If-None-Match: etag` when one is given. A 304
   * answers `{ body: null }` (the caller's copy is current); otherwise the
   * body comes back with the response's own `ETag`, or `null` when it sent
   * none.
   */
  getIfChanged<T>(path: string, etag: string | null): Observable<{ body: T | null; etag: string | null }> {
    const headers: Record<string, string> = etag ? { 'If-None-Match': etag } : {};
    return this.http.get<T>(this.url(path), { headers, observe: 'response', withCredentials: true }).pipe(
      map(response => ({ body: response.body, etag: response.headers.get('ETag') })),
      catchError((err: unknown) =>
        err instanceof HttpErrorResponse && err.status === 304
          ? of({ body: null, etag })
          : this.handleError(err as HttpErrorResponse)),
    );
  }

  /**
   * Walks every page of a `PaginatedResponse<T>` (`{items, total, page, page_size}`)
   * backend endpoint and emits the fully-accumulated array once — for admin-catalog
   * screens that were built around "give me everything" before the backend endpoint
   * paginated, so no consuming component has to change when the backend switches
   * from an unbounded `SELECT` to bounded `LIMIT`/`OFFSET` batches.
   *
   * Bounded by `maxItems` (F-012): the walk is sequential, so a catalog with a
   * large `total` costs `total / pageSize` round-trips before anything renders.
   * Past the ceiling this fails fast — on the first page's `total`, before a
   * single extra request goes out — rather than pinning the tab. A caller that
   * hits it wants server-side filtering (or a paged grid), not a bigger array.
   *
   * `firstPage` is the endpoint's page base (D-347). Every offset list on the
   * platform is one-based (D-793: no zero-based endpoint remains), so the
   * default `1` is right for all of them. The argument stays caller-supplied
   * rather than a path lookup on purpose: `@attome/base` is the generic layer
   * and does not get to know XRM's endpoint catalog.
   *
   * Passing the wrong base silently misbehaves. A one-based server clamps
   * page 0 to 1, so a walk started at 0 fetches page 1 twice; and the
   * zero-based check `(k + 1) * page_size < total` stops one page early
   * whenever a final page exists, dropping it with no error — what the
   * workflow admin lists did before D-347.
   */
  getAllPages<T>(
    path: string,
    extraParams: Record<string, string> = {},
    pageSize = 200,
    maxItems = MAX_ALL_PAGES_ITEMS,
    firstPage = 1,
  ): Observable<T[]> {
    const fetchPage = (page: number) =>
      this.get<Page<T>>(path, { ...extraParams, page: String(page), page_size: String(pageSize) });
    // `reduce`'s seed is captured when the pipe is built, not per subscription,
    // so the mutable accumulator has to be created inside `defer` — otherwise a
    // second subscription (a `retry`, a component subscribing twice) would keep
    // appending to the first one's array.
    return defer(() => fetchPage(firstPage).pipe(
      expand(res => {
        if (res.total > maxItems) throw tooManyPages(res.total, maxItems);
        // Count pages already consumed relative to the endpoint's own base, and
        // resume from the page the server says it served (`res.page`) rather
        // than the one we asked for — a handler that clamps an out-of-range page
        // reports the clamped value, and following it is what keeps the walk
        // aligned. On the default one-based walk this is
        // `res.page * res.page_size < res.total`.
        const consumed = res.page - firstPage + 1;
        // A `page_size` of 0 would make the "have we reached `total`" arithmetic
        // true forever; treat it as end-of-list instead of looping. `consumed <= 0`
        // guards the same way against a server echoing a page below the base.
        return res.page_size > 0 && consumed > 0 && consumed * res.page_size < res.total
          ? fetchPage(res.page + 1)
          : EMPTY;
      }),
      // `push` rather than `[...acc, ...res.items]`: the spread reallocated and
      // recopied the whole accumulation once per page (O(n²) over the walk).
      reduce<Page<T>, T[]>((acc, res) => {
        for (const item of res.items) acc.push(item);
        return acc;
      }, []),
    ));
  }

  /**
   * NGB-2.5 / OD-4b — the typed per-call option bag for a mutating request.
   * Credentials and CSRF stay with the interceptor, never here.
   */
  post<T>(path: string, body: unknown, options: WriteOptions = {}): Observable<T> {
    return this.http.post<T>(this.url(path), body, {
      headers: this.mutationHeaders(options, options.ifMatch),
      withCredentials: true,
    }).pipe(catchError(this.handleError));
  }

  put<T>(path: string, body: unknown, options: WriteOptions = {}): Observable<T> {
    return this.http.put<T>(this.url(path), body, {
      headers: this.mutationHeaders(options),
      withCredentials: true,
    }).pipe(catchError(this.handleError));
  }

  /**
   * `etag` is the record's `row_version`; it becomes an `If-Match` header and
   * preserves the established optimistic-concurrency contract.
   */
  patch<T>(path: string, body: unknown, etag?: number, options: WriteOptions = {}): Observable<T> {
    return this.http.patch<T>(this.url(path), body, {
      headers: this.mutationHeaders(options, etag),
      withCredentials: true,
    }).pipe(catchError(this.handleError));
  }

  delete(path: string, options: WriteOptions = {}): Observable<void> {
    return this.http.delete<void>(this.url(path), {
      headers: this.mutationHeaders(options),
      withCredentials: true,
    }).pipe(catchError(this.handleError));
  }

  private handleError(err: HttpErrorResponse): Observable<never> {
    // `HttpErrorResponse.message` embeds the full request URL, so it is never
    // surfaced — not even as a fallback. NGB-2.3 closes the other half of the
    // same hole: the server's `message` is English prose for every kind but
    // `validation` and `rule_violation`, so `ApiService` no longer invents a
    // default either. A body with no `message` leaves this empty and the UI
    // renders `LangService.errorText(err)`, which is language-correct for
    // every kind.
    const body = err.error;
    const error: ApiError = {
      status:  err.status,
      kind:    codeToKind(body?.error) ?? statusToKind(err.status),
      message: typeof body?.message === 'string' ? body.message : '',
    };
    if (typeof body?.error === 'string') error.code = body.error;
    // Solution 7 (D-785): a changeset refusal is a plain `conflict` on the
    // wire; its stable code is the message's prefix. Lifting it into `code`
    // is what makes the UI say "open a changeset first" or "owned by another
    // layer" instead of "someone else changed this first". `kind` stays
    // `conflict`, so every existing 409 branch still sees a conflict.
    if (error.kind === 'conflict') {
      const refusal = changesetRefusalCode(body?.message);
      if (refusal) {
        error.code = refusal;
        // The many screens that still print `err.message` show the server's
        // explanation without the `conflict: <code>:` plumbing in front of it.
        error.message = refusalProse(error.message, refusal);
      }
    }

    // NGB-2.1 — support correlates a UI error with the server's logs. The body
    // is authoritative; the header is the fallback for a response that carries
    // no JSON body at all (a proxy's 502, a 413 from the body-size guard).
    const headerId = err.headers?.get?.('x-request-id') ?? null;
    const requestId = typeof body?.request_id === 'string' ? body.request_id : headerId;
    if (typeof requestId === 'string' && requestId.length > 0) error.requestId = requestId;
    // M45 Phase 2 / D-472: `rule_violation` is the one code whose body answers
    // *which* rule refused the write. Kept for that code only — same posture as
    // the step-up fields below.
    if (error.kind === 'rule_violation' && typeof body?.rule_id === 'string') error.ruleId = body.rule_id;

    // D-789 (business rules): a `field_locked` / `field_locked_required`
    // refusal names the field, rule and effect at the top level and lists
    // every locked field in `details.fields`; a `rule_violation` may carry
    // `details.field`. Kept additively so a form can put the refusal under
    // its field instead of parsing the message. No record value is ever in
    // these members (the server echoes names only).
    const fieldLocked = body?.error === 'field_locked' || body?.error === 'field_locked_required';
    if (fieldLocked && typeof body?.rule_id === 'string') error.ruleId = body.rule_id;
    if (typeof body?.field === 'string') error.field = body.field;
    if (typeof body?.rule_name === 'string') error.ruleName = body.rule_name;
    if (typeof body?.effect === 'string') error.effect = body.effect;
    if (body?.details !== undefined && body?.details !== null) error.details = body.details;

    // A15-T4: a save refused as a likely duplicate names the records it
    // matches (only those the caller may read) and counts the rest.
    if (body?.error === 'duplicate_detected') {
      error.duplicates = {
        matches: Array.isArray(body?.matches) ? body.matches : [],
        hidden: typeof body?.hidden === 'number' ? body.hidden : 0,
      };
    }

    // D-510 rule 6: the step-up prompt is built from these two fields, so they
    // are the only extra body fields kept — and only for this one code.
    if (error.kind === 'reauth_required') {
      if (typeof body?.operation === 'string') error.operation = body.operation;
      error.acceptableFactors = Array.isArray(body?.acceptable_factors)
        ? body.acceptable_factors.filter((f: unknown): f is string => typeof f === 'string')
        : [];
    }
    return throwError(() => error);
  }
}

/**
 * Mirrors `AppError::into_response`'s `code` string
 * (`crates/foundation/attome-types/src/error.rs`) — the only signal that distinguishes
 * same-status variants (Conflict vs VersionConflict vs IdempotencyConflict, all
 * 409; the four 503s; the four 403s).
 *
 * NGB-2.1: one row per wire code. `every_wire_code_is_declared_on_every_contract_surface`
 * in attome-types is the Rust half of this table's drift guard (NGB-2.2 extends
 * it to read this file).
 */
function codeToKind(code: unknown): ApiError['kind'] | undefined {
  switch (code) {
    case 'not_found':                      return 'not_found';
    case 'unauthorized':                   return 'unauthorized';
    case 'forbidden':                      return 'forbidden';
    case 'conflict':                       return 'conflict';
    case 'duplicate_detected':             return 'conflict';
    case 'version_conflict':               return 'version_conflict';
    case 'idempotency_conflict':           return 'idempotency_conflict';
    case 'idempotency_outcome_unknown':    return 'idempotency_outcome_unknown';
    case 'idempotency_replay_unavailable': return 'idempotency_replay_unavailable';
    case 'validation_error':               return 'validation';
    case 'rule_violation':                 return 'rule_violation';
    case 'transition_not_allowed':         return 'transition_not_allowed';
    case 'internal_error':                 return 'internal';
    case 'reauth_required':                return 'reauth_required';
    case 'rate_limit_exceeded':            return 'rate_limited';
    case 'payload_too_large':              return 'payload_too_large';
    case 'request_rejected':               return 'validation';
    case 'feature_hidden':                 return 'feature_hidden';
    case 'metadata_authoring_locked':      return 'authoring_locked';
    case 'feature_unavailable':            return 'unavailable';
    case 'capability_unavailable':         return 'unavailable';
    case 'overloaded':                     return 'unavailable';
    case 'server_timeout':                 return 'unavailable';
    case 'read_only':                      return 'unavailable';
    default:                               return undefined;
  }
}

// Fallback when the body carries no recognized `error` code (network failure,
// non-JSON error page, etc.) — status alone can't distinguish conflict from
// version_conflict, so that pair is intentionally absent here. NGB-2.1 adds the
// three statuses that previously fell through to `unknown`.
function statusToKind(status: number): ApiError['kind'] {
  switch (status) {
    case 401: return 'unauthorized';
    case 403: return 'forbidden';
    case 404: return 'not_found';
    case 409: return 'conflict';
    case 413: return 'payload_too_large';
    case 422: return 'validation';
    case 429: return 'rate_limited';
    case 500: return 'internal';
    case 503: return 'unavailable';
    default:  return 'unknown';
  }
}
