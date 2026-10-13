import { Injectable } from '@angular/core';
import { Observable, timer } from 'rxjs';
import { last, switchMap, take, takeWhile } from 'rxjs/operators';

/** ~60 s of polling at the default 1 s interval; past that the job keeps
 * running server-side and the caller is told to check back later. */
export const DEFAULT_POLL_INTERVAL_MS = 1000;
export const DEFAULT_MAX_POLLS = 60;

export interface PollOptions {
  /** Milliseconds between polls. Default 1000. */
  intervalMs?: number;
  /** Polls stop being scheduled after this many, terminal or not. Default 60. */
  maxPolls?: number;
}

/**
 * Polls a durable job's status endpoint until it reaches a terminal state,
 * or `maxPolls` is reached — the one poll loop `entity-list`'s bulk edit
 * (`POST /api/v1/{entity}/bulk`) and CSV export (`POST /api/v1/{entity}/export`)
 * each hand-rolled identically (C-28). Fetches immediately (poll 0 fires at
 * `t=0`, not after the first interval), then every `intervalMs` — same
 * `timer(0, intervalMs)` shape both call sites already relied on.
 *
 * Resolves with the last status observed. The caller distinguishes "reached
 * a terminal state" from "gave up after `maxPolls`" the same way it always
 * has — by re-checking `isTerminal(result)` against what came back, since a
 * job that outlives the poll budget keeps running server-side and is not an
 * error this service can report on the caller's behalf.
 */
@Injectable({ providedIn: 'root' })
export class BulkJobRunner {
  poll<T>(
    fetchStatus: () => Observable<T>,
    isTerminal: (status: T) => boolean,
    options?: PollOptions,
  ): Observable<T> {
    const intervalMs = options?.intervalMs ?? DEFAULT_POLL_INTERVAL_MS;
    const maxPolls   = options?.maxPolls   ?? DEFAULT_MAX_POLLS;
    return timer(0, intervalMs).pipe(
      switchMap(() => fetchStatus()),
      takeWhile(status => !isTerminal(status), true),
      take(maxPolls),
      last(),
    );
  }
}

/** `automation_bulk_operation.status` values after which the worker will not touch the job again. */
export function isBulkTerminal(status: string): boolean {
  return status === 'completed' || status === 'failed';
}
