import { HttpClient, HttpErrorResponse, HttpHeaders, HttpParams, HttpResponse } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { AttomeClient, ApiError as SdkApiError, CHANGESET_HEADER } from '@attome/sdk';
import type { AuthProvider, AuthRequestContext, RequestOptions } from '@attome/sdk';
import { Observable } from 'rxjs';
import { ApiService, MAX_ALL_PAGES_ITEMS, apiErrorOf, walkAllPages, writeHeaders } from './api.service';
import type { Page, WriteOptions } from './api.service';
import { ATTOME_CONFIG } from './config';

/** The SDK needs an origin; this one stands for "the page's own" and is cut off again. */
const SAME_ORIGIN = 'https://same-origin.attome.invalid';

/**
 * Y9-T3: a `fetch` that sends through Angular's `HttpClient`, so a request
 * the generated `@attome/sdk` makes passes the app's interceptors (session
 * refresh, CSRF, request id) and a spec's `HttpTestingController` sees it, as
 * for every `ApiService` call. The answer comes back as a `Response`, error
 * statuses included, for the SDK to read.
 */
export function httpClientFetch(http: HttpClient): typeof fetch {
  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    // A same-origin deployment (`apiUrl: ''`) sends relative paths, as ApiService does.
    const full = raw.startsWith(SAME_ORIGIN) ? raw.slice(SAME_ORIGIN.length) : raw;
    // The query goes as HttpParams and a JSON body as an object, the shapes
    // ApiService sends, so interceptors and specs read them the same way.
    const at = full.indexOf('?');
    const url = at < 0 ? full : full.slice(0, at);
    const params = new HttpParams({ fromString: at < 0 ? '' : full.slice(at + 1) });
    const method = (init?.method ?? 'GET').toUpperCase();
    let headers = new HttpHeaders();
    new Headers(init?.headers).forEach((value, name) => {
      headers = headers.set(name, value);
    });
    let body: unknown = init?.body ?? null;
    if (typeof body === 'string' && (headers.get('content-type') ?? '').includes('application/json')) {
      body = JSON.parse(body) as unknown;
    }
    const request = http.request(method, url, {
      body,
      headers,
      params,
      observe: 'response',
      responseType: 'json',
      withCredentials: true,
    });
    // The SDK's signal cancels the request; one that ends with no answer (a
    // test tearing down) is an abort too, never an unanswered promise.
    const signal = init?.signal ?? undefined;
    const answer = await new Promise<HttpResponse<unknown> | HttpErrorResponse>((resolve, reject) => {
      const aborted = (): void => reject(new DOMException('The request was cancelled', 'AbortError'));
      if (signal?.aborted) return aborted();
      let settled = false;
      const subscription = request.subscribe({
        next: response => {
          if (response instanceof HttpResponse) {
            settled = true;
            resolve(response);
          }
        },
        error: (err: unknown) => {
          settled = true;
          if (err instanceof HttpErrorResponse) resolve(err);
          else reject(err);
        },
        complete: () => {
          if (!settled) aborted();
        },
      });
      signal?.addEventListener('abort', () => {
        subscription.unsubscribe();
        if (!settled) aborted();
      }, { once: true });
    });
    let text: string | null;
    if (answer instanceof HttpErrorResponse) {
      // A 2xx whose body is not JSON arrives as a parse failure carrying the text.
      const failed = answer.error as { text?: unknown } | string | null;
      text = typeof failed === 'string' ? failed
        : failed && typeof failed.text === 'string' && answer.status >= 200 && answer.status < 300 ? failed.text
          : JSON.stringify(failed ?? null);
    } else {
      text = answer.body === null ? null : JSON.stringify(answer.body);
    }
    const status = answer.status === 0 ? 599 : answer.status;
    const out = new Headers();
    for (const name of answer.headers.keys()) {
      const value = answer.headers.get(name);
      if (value !== null) out.set(name, value);
    }
    // HttpClient parsed the answer as JSON; say so, for the SDK reads by content type.
    if (text !== null && !out.has('content-type')) out.set('content-type', 'application/json');
    // A 204 or 304 answer has no body.
    return new Response(status === 204 || status === 304 ? null : text, { status, headers: out });
  };
}

/**
 * The session the browser holds is the credential (its cookie, sent with
 * `withCredentials`); the provider only names the changeset a mutating
 * request records into, as `ApiService` does.
 */
class AppSessionAuth implements AuthProvider {
  readonly credentialsMode: RequestCredentials = 'include';
  constructor(private readonly changeset: () => string | null) {}
  applyAuth(ctx: AuthRequestContext): void {
    const id = this.changeset();
    if (id && ctx.method !== 'GET' && !ctx.headers.has(CHANGESET_HEADER)) {
      ctx.headers.set(CHANGESET_HEADER, id);
    }
  }
}

/** `opts` with ApiService's write options as their headers. */
function withWrite(opts: RequestOptions | undefined, write: WriteOptions | undefined): RequestOptions | undefined {
  if (!write) return opts;
  const ifMatch = write.ifMatch ?? opts?.ifMatch;
  return {
    ...opts,
    ifMatch,
    headers: { ...writeHeaders({ ...write, ifMatch: undefined }), ...opts?.headers },
  };
}

/**
 * Y9-T3: the generated `@attome/sdk` client for the app's data services,
 * through `HttpClient` ([`httpClientFetch`]). Each call is an `Observable` of
 * the body; a refusal is the same `ApiError` `ApiService` raises
 * (`apiErrorOf`), so a component handles both clients' errors alike.
 */
@Injectable({ providedIn: 'root' })
export class SdkService {
  private readonly api = inject(ApiService);
  readonly client = new AttomeClient({
    baseUrl: inject(ATTOME_CONFIG).apiUrl || SAME_ORIGIN,
    // A test's stand-in ApiService may have no changeset to name.
    auth: new AppSessionAuth(() => (typeof this.api.activeChangeset === 'function' ? this.api.activeChangeset() : null)),
    fetch: httpClientFetch(inject(HttpClient)),
    timeoutMs: 0,
  });

  get<T>(path: string, opts?: RequestOptions): Observable<T> {
    return this.call(signal => this.client.get<T>(path, { ...opts, signal }));
  }

  /**
   * `write` is ApiService's option bag (idempotency key, operation id,
   * duplicate reason, merge, background, `ifMatch`), sent as the same headers.
   */
  post<T>(path: string, opts?: RequestOptions, write?: WriteOptions): Observable<T> {
    return this.call(signal => this.client.post<T>(path, { ...withWrite(opts, write), signal }));
  }

  patch<T>(path: string, opts?: RequestOptions, write?: WriteOptions): Observable<T> {
    return this.call(signal => this.client.patch<T>(path, { ...withWrite(opts, write), signal }));
  }

  put<T>(path: string, opts?: RequestOptions, write?: WriteOptions): Observable<T> {
    return this.call(signal => this.client.put<T>(path, { ...withWrite(opts, write), signal }));
  }

  delete<T = void>(path: string, opts?: RequestOptions): Observable<T> {
    return this.call(signal => this.client.delete<T>(path, { ...opts, signal }));
  }

  /**
   * Every item of a paged list, as `ApiService.getAllPages` walks it (the same
   * ceiling and `too_many_pages` refusal), through the SDK.
   */
  getAllPages<T>(
    path: string,
    extraParams: Record<string, string> = {},
    pageSize = 200,
    maxItems = MAX_ALL_PAGES_ITEMS,
    firstPage = 1,
  ): Observable<T[]> {
    const fetchPage = (page: number): Observable<Page<T>> =>
      this.get<Page<T>>(path, { query: { ...extraParams, page: String(page), page_size: String(pageSize) } });
    return walkAllPages(fetchPage, maxItems, firstPage);
  }

  /**
   * One SDK call as an Observable: unsubscribing aborts the request, and an
   * aborted call emits nothing (no error a subscriber has left).
   */
  private call<T>(send: (signal: AbortSignal) => Promise<{ data: T }>): Observable<T> {
    return new Observable<T>(subscriber => {
      const controller = new AbortController();
      send(controller.signal).then(
        response => {
          // An empty answer (a 204) is null, as HttpClient gives it.
          subscriber.next((response.data === undefined ? null : response.data) as T);
          subscriber.complete();
        },
        (err: unknown) => {
          if (controller.signal.aborted) return;
          // HttpClient ended with no answer: complete quietly, as ApiService does.
          if (err instanceof DOMException && err.name === 'AbortError') {
            subscriber.complete();
            return;
          }
          subscriber.error(err instanceof SdkApiError
            ? apiErrorOf(err.status, err.body, err.requestId ?? null)
            : err);
        },
      );
      return () => controller.abort();
    });
  }
}
