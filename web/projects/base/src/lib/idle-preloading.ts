import { Injectable } from '@angular/core';
import { PreloadingStrategy, Route } from '@angular/router';
import { Observable, EMPTY, defer, switchMap, timer } from 'rxjs';

/** How long to wait for an idle moment before preloading anyway. */
export const IDLE_PRELOAD_TIMEOUT_MS = 4_000;

/**
 * AA12-T1: loads the code of the screens a person is likely to open next
 * while the browser has nothing else to do. A route opts in with
 * `data: { preload: true }`; its chunk is fetched at the next idle moment
 * (or after {@link IDLE_PRELOAD_TIMEOUT_MS}), and never when the person asked
 * the browser to save data or is on a 2G connection.
 */
@Injectable({ providedIn: 'root' })
export class IdlePreloading implements PreloadingStrategy {
  preload(route: Route, load: () => Observable<unknown>): Observable<unknown> {
    if (route.data?.['preload'] !== true || !preloadAllowed()) return EMPTY;
    return defer(() => whenIdle()).pipe(switchMap(() => load()));
  }
}

/** False when the person asked to save data or the connection is very slow. */
export function preloadAllowed(nav: unknown = typeof navigator === 'undefined' ? undefined : navigator): boolean {
  const connection = (nav as { connection?: { saveData?: boolean; effectiveType?: string } } | undefined)?.connection;
  if (!connection) return true;
  return !connection.saveData && !/(^|-)2g$/.test(connection.effectiveType ?? '');
}

/** Resolves at the browser's next idle moment, or after the timeout without `requestIdleCallback`. */
function whenIdle(): Observable<unknown> {
  const idle = (globalThis as { requestIdleCallback?: (cb: () => void, opts?: { timeout: number }) => number })
    .requestIdleCallback;
  if (!idle) return timer(IDLE_PRELOAD_TIMEOUT_MS);
  return new Observable<void>(subscriber => {
    idle(() => {
      subscriber.next();
      subscriber.complete();
    }, { timeout: IDLE_PRELOAD_TIMEOUT_MS });
  });
}
