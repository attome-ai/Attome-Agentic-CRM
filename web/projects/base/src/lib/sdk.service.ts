import { HttpClient, HttpErrorResponse, HttpHeaders } from '@angular/common/http';
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
    const url = raw.startsWith(SAME_ORIGIN) ? raw.slice(SAME_ORIGIN.length) : raw;
    const method = (init?.method ?? 'GET').toUpperCase();
    let headers = new HttpHeaders();
    new Headers(init?.headers).forEach((value, name) => {
      headers = headers.set(name, value);
    });
    const body = typeof init?.body === 'string' ? init.body : init?.body ?? null;
    const answer = await firstValueFrom(
      http.request(method, url, {
        body,
        headers,
        observe: 'response',
        responseType: 'text',
        withCredentials: true,
      }),
    ).catch((err: unknown) => {
      if (err instanceof HttpErrorResponse) return err;
      throw err;
    });
    const text = answer instanceof HttpErrorResponse
      ? (typeof answer.error === 'string' ? answer.error : JSON.stringify(answer.error ?? null))
      : (answer.body ?? '');
    const out = new Headers();
    for (const name of answer.headers.keys()) {
      const value = answer.headers.get(name);
      if (value !== null) out.set(name, value);
    }
    const status = answer.status === 0 ? 599 : answer.status;
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
