import type { AuthProvider } from './auth/types';
import { IDEMPOTENCY_KEY_HEADER } from './idempotency';
import { IF_MATCH_HEADER, IF_NONE_MATCH_HEADER, ifMatchValue } from './concurrency';
import { mapErrorResponse } from './errors';

/** Solution 7 (D-785): names the open changeset a metadata admin write
 * records into. The server refuses it on an S2S-signed request (422), so pair
 * it with `ApiKeyAuth` or `SessionAuth` only. */
export const CHANGESET_HEADER = 'X-Attome-Changeset';

const MUTATING_METHODS: ReadonlySet<string> = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export interface AttomeClientOptions {
  /** Deployment origin, no trailing slash and no `/api` suffix — paths
   * passed to `request`/`get`/... already carry the full `/api/v1/...`
   * prefix, matching `openapi.json`. E.g. `"http://localhost:7865"`. */
  baseUrl: string;
  /** One of `ApiKeyAuth`, `SessionAuth`, `S2sAuth` — or a custom `AuthProvider`. */
  auth: AuthProvider;
  /** Defaults to `globalThis.fetch`. Override to inject a mock in tests or
   * to run in a runtime with no global `fetch`. */
  fetch?: typeof fetch;
  /** Aborts a request after this many milliseconds. `0` disables the
   * timeout. Default 30000. */
  timeoutMs?: number;
  /** Merged into every request's headers at the lowest precedence (a
   * per-call header in `RequestOptions.headers` wins). */
  defaultHeaders?: Record<string, string>;
  /** Solution 7 (D-785): the open changeset every mutating request (`POST`,
   * `PUT`, `PATCH`, `DELETE`) records into, sent as `X-Attome-Changeset`.
   * Omit it to let the server pick the caller's single open changeset (or,
   * per its mode, refuse with 409 `changeset_required` / auto-record).
   * Override per call with `RequestOptions.changesetId`. */
  changesetId?: string;
}

export interface RequestOptions {
  query?: Record<string, string | number | boolean | undefined | null>;
  /** JSON-serialized unless already a `Uint8Array` (sent as-is) or a
   * `string` (sent as `text/plain` unless `headers['content-type']` is set). */
  body?: unknown;
  headers?: Record<string, string>;
  /** Sets `Idempotency-Key` — see `idempotency.ts`. Only meaningful on a
   * mutating method; the server ignores it on a safe one. */
  idempotencyKey?: string;
  /** Sets `If-Match` from a `row_version` — see `concurrency.ts`. Required
   * by the server on every entity `PATCH`. */
  ifMatch?: number | string;
  /** Sets `If-None-Match` from a `row_version`, for a conditional `GET`. */
  ifNoneMatch?: number | string;
  /** Overrides `AttomeClientOptions.changesetId` for this call; `null` sends
   * no `X-Attome-Changeset` even when the client has one. Mutating methods
   * only. */
  changesetId?: string | null;
  signal?: AbortSignal;
}

export interface ApiResponse<T> {
  data: T;
  status: number;
  headers: Headers;
  requestId?: string;
}

function buildQuery(query: RequestOptions['query']): string {
  if (!query) return '';
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null) continue;
    params.set(key, String(value));
  }
  return params.toString();
}

/** Combines zero or more `AbortSignal`s. Uses `AbortSignal.any` where
 * available (Node 20+, current browsers); falls back to the first defined
 * signal on an older runtime rather than failing outright — timeout-only
 * cancellation still works there, just not alongside a caller-supplied
 * `signal` at the same time. */
function combineSignals(...signals: (AbortSignal | undefined)[]): AbortSignal | undefined {
  const present = signals.filter((s): s is AbortSignal => !!s);
  if (present.length === 0) return undefined;
  if (present.length === 1) return present[0];
  const anyFn = (AbortSignal as unknown as { any?: (list: AbortSignal[]) => AbortSignal }).any;
  return anyFn ? anyFn(present) : present[0];
}

/** Low-level HTTP transport: builds the request (query, body, auth,
 * idempotency/If-Match headers), sends it, and maps a non-2xx response to
 * `ApiError`. `AttomeClient` (and any generated per-endpoint helpers) sit on
 * top of this — this is also the layer a caller reaches for directly when
 * they want the full typed request/response envelope (`ApiResponse<T>`)
 * rather than just the body. */
export class AttomeTransport {
  private readonly baseUrl: string;
  private readonly auth: AuthProvider;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;
  private readonly defaultHeaders: Record<string, string>;
  private readonly changesetId: string | undefined;

  constructor(options: AttomeClientOptions) {
    if (!options.baseUrl) {
      throw new Error('AttomeClientOptions.baseUrl is required');
    }
    this.baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.auth = options.auth;
    const fetchImpl = options.fetch ?? globalThis.fetch;
    if (!fetchImpl) {
      throw new Error(
        'No fetch implementation available — pass `fetch` explicitly in a runtime with no global fetch',
      );
    }
    this.fetchImpl = fetchImpl;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.defaultHeaders = options.defaultHeaders ?? {};
    this.changesetId = options.changesetId?.trim() || undefined;
  }

  async request<T>(method: string, path: string, opts: RequestOptions = {}): Promise<ApiResponse<T>> {
    const queryString = buildQuery(opts.query);
    const pathAndQuery = queryString ? `${path}${path.includes('?') ? '&' : '?'}${queryString}` : path;
    const url = `${this.baseUrl}${pathAndQuery}`;

    const headers = new Headers(this.defaultHeaders);
    let bodyBytes: Uint8Array | null = null;
    let bodyInit: BodyInit | undefined;
    if (opts.body !== undefined) {
      if (opts.body instanceof Uint8Array) {
        bodyBytes = opts.body;
        bodyInit = new Uint8Array(opts.body); // copy: BodyInit narrowing keeps TS happy across DOM lib versions
      } else if (typeof opts.body === 'string') {
        bodyBytes = new TextEncoder().encode(opts.body);
        bodyInit = opts.body;
      } else {
        const json = JSON.stringify(opts.body);
        bodyBytes = new TextEncoder().encode(json);
        bodyInit = json;
        headers.set('content-type', 'application/json');
      }
    }

    for (const [key, value] of Object.entries(opts.headers ?? {})) headers.set(key, value);
    if (opts.idempotencyKey) headers.set(IDEMPOTENCY_KEY_HEADER, opts.idempotencyKey);
    if (opts.ifMatch !== undefined) headers.set(IF_MATCH_HEADER, ifMatchValue(opts.ifMatch));
    if (opts.ifNoneMatch !== undefined) headers.set(IF_NONE_MATCH_HEADER, ifMatchValue(opts.ifNoneMatch));
    const changesetId = opts.changesetId === undefined ? this.changesetId : opts.changesetId?.trim() || undefined;
    if (changesetId && MUTATING_METHODS.has(method.toUpperCase())) headers.set(CHANGESET_HEADER, changesetId);

    await this.auth.applyAuth({ method, pathAndQuery, headers, body: bodyBytes });

    const timeoutSignal = this.timeoutMs > 0 ? AbortSignal.timeout(this.timeoutMs) : undefined;
    const response = await this.fetchImpl(url, {
      method,
      headers,
      body: bodyInit,
      credentials: this.auth.credentialsMode,
      signal: combineSignals(opts.signal, timeoutSignal),
    });

    const requestId = response.headers.get('x-request-id') ?? undefined;
    const contentType = response.headers.get('content-type') ?? '';
    const raw = await response.text();
    let data: unknown;
    if (raw.length === 0) {
      data = undefined;
    } else if (/[/+]json\b/.test(contentType)) {
      data = JSON.parse(raw);
    } else {
      data = raw;
    }

    if (!response.ok) {
      throw mapErrorResponse(response.status, requestId ?? null, data);
    }

    return { data: data as T, status: response.status, headers: response.headers, requestId };
  }
}
