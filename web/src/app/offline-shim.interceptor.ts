import { HttpErrorResponse, HttpEvent, HttpInterceptorFn, HttpRequest } from '@angular/common/http';
import { EnvironmentInjector, inject, runInInjectionContext } from '@angular/core';
import { Observable, catchError, from, switchMap, tap, throwError } from 'rxjs';

/** Requests the offline data path can answer: the record API and the schema. */
const API = /^(?:https?:\/\/[^/]+)?\/api\/v1\//;

type Offline = typeof import('@attome/xrm/offline');
let module: Promise<Offline> | null = null;
const load = (): Promise<Offline> => (module ??= import('@attome/xrm/offline'));

/**
 * B18-T8: the host's hook into `@attome/xrm/offline`'s data path, loaded
 * only when needed so the offline store and the rule evaluator stay out of
 * the first page's bundle. Offline (or when a request fails for want of a
 * network), an API request goes to `answerOffline`; online, schema answers
 * are handed to `keepSchema` for later.
 */
export const offlineShimInterceptor: HttpInterceptorFn = (req, next) => {
  if (!API.test(req.url)) return next(req);
  const injector = inject(EnvironmentInjector);
  const answer = (): Observable<HttpEvent<unknown>> =>
    from(load()).pipe(switchMap(m => runInInjectionContext(injector, () => m.answerOffline(req as HttpRequest<unknown>))));
  if (typeof navigator !== 'undefined' && navigator.onLine === false) return answer();
  const isSchema = req.method === 'GET' && req.url.includes('/api/v1/schema/');
  return next(req).pipe(
    tap(event => {
      if (isSchema) void load().then(m => runInInjectionContext(injector, () => m.keepSchema(req, event))).catch(() => undefined);
    }),
    catchError((e: unknown) => (e instanceof HttpErrorResponse && e.status === 0 ? answer() : throwError(() => e))),
  );
};
