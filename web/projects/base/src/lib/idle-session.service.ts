import { DestroyRef, Injectable, computed, inject, signal } from '@angular/core';
import { DOCUMENT } from '@angular/common';
import { Observable, Subject } from 'rxjs';
import { ApiService } from './api.service';
import type { SessionInfo } from './types';

/** How long before the idle sign-out the warning shows. */
export const IDLE_WARNING_SECS = 60;
/** Pointer and key activity is noted at most this often. */
export const ACTIVITY_THROTTLE_MS = 30_000;

/**
 * Q8-T9: the browser side of the session idle timeout (Q8-T1, Q8-T3). The
 * person's roles set `idle_secs` (from `GET /api/v1/auth/session`); pointer
 * and key events, noted at most once per 30 s, count as activity. A minute
 * before the idle limit the warning shows a countdown; at the limit
 * `beforeIdleSignOut` fires, so an open form can keep a local draft, and the
 * session ends. Activity the server has not seen (no request since) is told
 * to it with a plain session read, so its idle clock agrees with this one;
 * background polling never counts (`x-attome-background: 1`).
 */
@Injectable({ providedIn: 'root' })
export class IdleSessionService {
  private readonly api = inject(ApiService);
  private readonly document = inject(DOCUMENT);

  private readonly idleSecs = signal<number | null>(null);
  private readonly lastActivity = signal(Date.now());
  private readonly now = signal(Date.now());
  private lastServerTouch = Date.now();
  private lastNoted = 0;
  private ticker: ReturnType<typeof setInterval> | null = null;
  private readonly signOut$ = new Subject<void>();

  /** Fires once just before an idle sign-out; save drafts here. */
  readonly beforeIdleSignOut: Observable<void> = this.signOut$.asObservable();

  /** Seconds until the idle sign-out, or `null` when no limit applies. */
  readonly secondsLeft = computed(() => {
    const idle = this.idleSecs();
    if (idle === null || idle <= 0) return null;
    return Math.max(0, Math.ceil(idle - (this.now() - this.lastActivity()) / 1000));
  });

  /** Whether the warning is showing. */
  readonly warning = computed(() => {
    const left = this.secondsLeft();
    return left !== null && left <= IDLE_WARNING_SECS;
  });

  private readonly onActivity = () => this.noteActivity();

  /**
   * Starts watching with the session's idle limit (seconds; `null` or 0 for
   * none). `onExpired` signs the person out once the limit passes.
   */
  start(idleSecs: number | null, onExpired: () => void, destroyRef?: DestroyRef): void {
    this.stop();
    this.idleSecs.set(idleSecs);
    this.lastActivity.set(Date.now());
    this.lastServerTouch = Date.now();
    if (!idleSecs || idleSecs <= 0) return;
    for (const type of ['pointerdown', 'keydown']) {
      this.document.addEventListener(type, this.onActivity, { passive: true });
    }
    this.ticker = setInterval(() => {
      this.now.set(Date.now());
      if (this.secondsLeft() === 0) {
        this.signOut$.next();
        this.stop();
        onExpired();
      }
    }, 1000);
    destroyRef?.onDestroy(() => this.stop());
  }

  /**
   * Reads the signed-in person's idle limit from `GET /api/v1/auth/session`
   * and starts watching; a failed read watches nothing.
   */
  startFromSession(onExpired: () => void, destroyRef?: DestroyRef): void {
    this.api.get<SessionInfo>('/api/v1/auth/session').subscribe({
      next: info => this.start(info.idle_secs ?? null, onExpired, destroyRef),
      error: () => undefined,
    });
  }

  stop(): void {
    if (this.ticker !== null) clearInterval(this.ticker);
    this.ticker = null;
    for (const type of ['pointerdown', 'keydown']) {
      this.document.removeEventListener(type, this.onActivity);
    }
    this.idleSecs.set(null);
  }

  /** "Stay signed in": counts as activity and tells the server at once. */
  stay(): void {
    this.lastNoted = 0;
    this.noteActivity(true);
  }

  /** A person's action, noted at most once per {@link ACTIVITY_THROTTLE_MS}. */
  noteActivity(force = false): void {
    const at = Date.now();
    if (!force && at - this.lastNoted < ACTIVITY_THROTTLE_MS) return;
    this.lastNoted = at;
    this.lastActivity.set(at);
    this.now.set(at);
    if (force || at - this.lastServerTouch >= ACTIVITY_THROTTLE_MS) {
      this.lastServerTouch = at;
      this.api.get('/api/v1/auth/session').subscribe({ error: () => undefined });
    }
  }
}
