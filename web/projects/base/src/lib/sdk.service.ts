import { HttpClient, HttpErrorResponse, HttpHeaders, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { AttomeClient, ApiError as SdkApiError, CHANGESET_HEADER } from '@attome/sdk';
import type { AuthProvider, AuthRequestContext, RequestOptions } from '@attome/sdk';
import { Observable, catchError, defer, firstValueFrom, from, map, throwError } from 'rxjs';
import { ApiService, apiErrorOf } from './api.service';
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
    const answer = await firstValueFrom(
      http.request(method, url, {
        body,
        headers,
        params,
        observe: 'response',
        responseType: 'json',
        withCredentials: true,
      }),
    ).catch((err: unknown) => {
      if (err instanceof HttpErrorResponse) return err;
      throw err;
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
    auth: new AppSessionAuth(() => this.api.activeChangeset()),
    fetch: httpClientFetch(inject(HttpClient)),
    timeoutMs: 0,
  });

  get<T>(path: string, opts?: RequestOptions): Observable<T> {
    return this.call(() => this.client.get<T>(path, opts));
  }

  post<T>(path: string, opts?: RequestOptions): Observable<T> {
    return this.call(() => this.client.post<T>(path, opts));
  }

  patch<T>(path: string, opts?: RequestOptions): Observable<T> {
    return this.call(() => this.client.patch<T>(path, opts));
  }

  put<T>(path: string, opts?: RequestOptions): Observable<T> {
    return this.call(() => this.client.put<T>(path, opts));
  }

  delete<T>(path: string, opts?: RequestOptions): Observable<T> {
    return this.call(() => this.client.delete<T>(path, opts));
  }

  private call<T>(send: () => Promise<{ data: T }>): Observable<T> {
    return defer(() => from(send())).pipe(
      map(response => response.data),
      catchError((err: unknown) =>
        throwError(() => (err instanceof SdkApiError
          ? apiErrorOf(err.status, err.body, err.requestId ?? null)
          : err)),
      ),
    );
  }
}
