import { HttpErrorResponse, HttpInterceptorFn, HttpRequest } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Router } from '@angular/router';
import { Observable, catchError, finalize, shareReplay, switchMap, throwError } from 'rxjs';
import { ATTOME_CONFIG } from './config';
import { AuthService } from './auth.service';

function isIdempotent(req: HttpRequest<unknown>): boolean {
  return req.method === 'GET' || req.method === 'HEAD';
}

/**
 * NGB-2.5 / OD-4b — a *keyed* write is safe to repeat: the server replays the
 * stored response for the same `x-idempotency-key` instead of running the
 * handler twice (`attome_server::middleware::idempotency`). An unkeyed write is
 * still never retried automatically.
 */
function isRetryable(req: HttpRequest<unknown>): boolean {
  return isIdempotent(req) || req.headers.has('x-idempotency-key') || req.headers.has('idempotency-key');
}

// Endpoints where a 401 is itself the answer (bad credentials, an expired
// one-time token, a stale MFA challenge) rather than a signal that the access
// cookie expired mid-session. `/auth/refresh` MUST stay in this list — it's
// what `refreshSession()` below calls, and that request re-enters this same
// interceptor, so excluding it is what stops the loop.
//
// Deliberately NOT excluded: `/auth/session` (bootstrapSession) and the
// session-gated MFA self-service endpoints (`mfa/status`, `mfa/enroll`,
// `mfa/confirm`, `mfa/disable`, `mfa/recovery-codes/regenerate`) — those
// require an existing session same as any other protected API call, so a 401
// there means the access cookie expired and should go through the normal
// refresh-and-retry path instead of being treated as "logged out".
const CREDENTIAL_ENDPOINTS = [
  '/api/v1/auth/login',
  '/api/v1/auth/register',
  '/api/v1/auth/refresh',
  '/api/v1/auth/mfa/verify',
  '/api/v1/auth/mfa/verify-recovery',
  '/api/v1/auth/mfa/pending-enroll',
  '/api/v1/auth/mfa/pending-confirm',
  '/api/v1/auth/reset-confirm',
  '/api/v1/auth/verify-email/confirm',
  '/api/v1/auth/google',
];

const SESSION_BOOTSTRAP_PATH = '/api/v1/auth/session';

/**
 * The pathname of a request that may carry a query string or a fragment.
 * `null` when it cannot be parsed, which the callers below treat as "no
 * match" — the fail-open direction for a credential endpoint would be to
 * refresh a 401 that is itself the answer.
 */
function pathnameOf(url: string): string | null {
  try {
    const base = typeof location !== 'undefined' ? location.href : 'http://localhost/';
    return new URL(url, base).pathname;
  } catch {
    return null;
  }
}

/**
 * NGB-F4: exact pathname matching, never `url.includes(path)`.
 * `/api/v1/auth/google/config` (a public config GET) used to match
 * `/api/v1/auth/google` (the login endpoint) and a 401 there was never
 * refreshed; so did `/api/v1/auth/register/config`. A query string that
 * happens to contain `/api/v1/auth/login` used to be treated as the login
 * endpoint itself.
 */
function isCredentialEndpoint(url: string): boolean {
  const path = pathnameOf(url);
  return path !== null && CREDENTIAL_ENDPOINTS.includes(path);
}

/**
 * D-510 rules 6 and 9: a 401 whose body `error` is `reauth_required` means the
 * session is alive but this one operation needs a fresh step-up. It is never an
 * expired session, so it must not refresh (a refresh cannot satisfy it), must
 * not retry, must not clear the session and must not navigate to login. The
 * caller — `StepUpService.run` — prompts and retries once.
 */
function isReauthRequired(err: HttpErrorResponse): boolean {
  const body: unknown = err.error;
  return typeof body === 'object' && body !== null
    && (body as { error?: unknown }).error === 'reauth_required';
}

// bootstrapSession()'s own GET — a 401 here (with a failed refresh behind it)
// just means "never logged in", the ordinary state for any anonymous visitor
// to a public page. AuthService.bootstrapSession() already handles that
// gracefully (resolves `null`, no error). Forcibly navigating to `loginRoute`
// in that case would hijack every anonymous page load (landing, /login,
// /register, ...) into a redirect, which is only correct when a *previously
// live* session has expired mid-use on some other request.
function isSessionBootstrapEndpoint(url: string): boolean {
  return pathnameOf(url) === SESSION_BOOTSTRAP_PATH;
}

/**
 * G13-T2: a web portal's own API, `/{keyword}/api/v1/...` (the portal
 * session, not the staff one). Its 401 means the portal user is signed out of
 * that portal; refreshing the staff session cannot help, and navigating to the
 * staff login would take a portal visitor somewhere they cannot sign in. The
 * page handles it.
 */
function isPortalRequest(url: string): boolean {
  const path = pathnameOf(url);
  return path !== null && !path.startsWith('/api/') && /^\/[^/]+\/api\/v1\//.test(path);
}

/**
 * Whether this request targets something this app owns — a relative URL (always
 * same-origin) or its configured API origin.
 *
 * Everything else is a third-party origin the browser talks to directly, and
 * today that means exactly one thing: the object store's presigned upload and
 * download URLs (`file-upload.service.ts`, D-144). Those must not be
 * credentialed, and the reason is the browser, not the store: a presigned URL
 * signs (method, path, expiry) and nothing else, so cookies grant no extra
 * authority — but `withCredentials: true` changes what CORS response the
 * browser will accept. A wildcard `Access-Control-Allow-Origin: *` stops being
 * valid; the store would have to echo the exact origin *and* send
 * `Access-Control-Allow-Credentials: true`. RustFS (like MinIO and S3) answers
 * `*` with no credentials header, so blanket-crediting every request failed
 * every upload at the preflight, before a single byte moved.
 *
 * A 401 from such an origin is likewise not this session's problem, so those
 * requests skip the refresh-and-retry path below too.
 */
function isAppRequest(reqUrl: string, apiUrl: string): boolean {
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(reqUrl)) return true;
  try {
    const base = typeof location !== 'undefined' ? location.href : undefined;
    return new URL(reqUrl).origin === new URL(apiUrl, base).origin;
  } catch {
    return false;
  }
}

/**
 * P-session-refresh-hardening (D-129): the one refresh in flight, shared by
 * every concurrent 401.
 *
 * NGB-F5: `providedIn: 'root'` rather than a module-level variable. Sending N
 * independent `POST /auth/refresh` calls for N concurrent 401s isn't just
 * wasteful — it's exactly the shape `refresh::redeem`'s reuse-detection can't
 * distinguish from a stolen token being replayed, and would revoke the whole
 * rotation family (backend `refresh.rs` doc comment). Single-flight must hold
 * per injector, not per module: two app instances in one page (or two TestBed
 * injectors in one `isolate: false` spec run) are two independent sessions and
 * must not share one refresh.
 */
@Injectable({ providedIn: 'root' })
export class RefreshCoordinator {
  private inFlight: Observable<unknown> | null = null;

  /**
   * Returns the in-flight refresh, starting one through `refresh` when none is
   * running. Reset to `null` in `finalize` so a later 401 (after this one
   * resolves, success or failure) starts a fresh refresh rather than replaying
   * a stale result.
   */
  run(refresh: () => Observable<unknown>): Observable<unknown> {
    this.inFlight ??= refresh().pipe(
      finalize(() => { this.inFlight = null; }),
      shareReplay(1),
    );
    return this.inFlight;
  }
}

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const auth        = inject(AuthService);
  const router      = inject(Router);
  const config      = inject(ATTOME_CONFIG);
  const coordinator = inject(RefreshCoordinator);
  const loginRoute  = config.loginRoute ?? '/login';

  if (!isAppRequest(req.url, config.apiUrl)) {
    return next(req);
  }

  const withCreds = req.clone({ withCredentials: true });

  return next(withCreds).pipe(
    catchError((err: unknown) => {
      // Rethrown untouched: anything that isn't a 401, a 401 that is itself
      // the answer (credential endpoints), and a `reauth_required` 401, which
      // is a step-up prompt rather than an expired session (see above).
      if (
        !(err instanceof HttpErrorResponse)
        || err.status !== 401
        || isCredentialEndpoint(req.url)
        || isReauthRequired(err)
        || isPortalRequest(req.url)
      ) {
        return throwError(() => err);
      }

      return coordinator.run(() => auth.refreshSession().pipe(
        catchError(refreshErr => {
          auth.clearSession();
          if (!isSessionBootstrapEndpoint(req.url)) {
            router.navigate([loginRoute], { queryParams: { returnUrl: router.url } });
          }
          return throwError(() => refreshErr);
        }),
      )).pipe(
        switchMap(() => {
          // NGB-2.5: a GET/HEAD, or a write carrying an idempotency key, is
          // safe to repeat. Any other write surfaces the original 401 so the
          // caller decides whether to resubmit — an auto-retried unkeyed POST
          // could double-submit if the first attempt actually reached the
          // handler before the token expired mid-flight.
          if (!isRetryable(withCreds)) {
            return throwError(() => err);
          }
          return next(withCreds);
        }),
      );
    }),
  );
};
