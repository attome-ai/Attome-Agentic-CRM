import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { DestroyRef, Injectable, computed, inject, signal } from '@angular/core';
import { Observable, catchError, tap, throwError } from 'rxjs';
import { ApiService } from './api.service';
import { ATTOME_CONFIG } from './config';

/**
 * Q13-T1: the request header naming a view-as or act-as session
 * (`attome_server::impersonation::HEADER`).
 */
export const IMPERSONATION_HEADER = 'x-attome-impersonation';

/** The session routes, which always run as the administrator. */
export const IMPERSONATION_ROUTES = '/api/v1/admin/security/impersonation';

/** A live session, as `POST /api/v1/admin/security/impersonation` returns it. */
export interface ImpersonationSession {
  id: string;
  subject_id: string;
  /** `view` or `act`. */
  mode: string;
  expires_at: string;
  /** Shown in the banner: the person's name or email, as the starter knew it. */
  subject_label?: string;
}

const STORAGE_KEY = 'attome-impersonation';

/**
 * Q13-T2 — the session this browser tab works in, if any. Kept in
 * `sessionStorage` so a reload stays in it and a new tab does not; cleared
 * when it expires, when it is ended, and when the server says it has ended.
 * The server decides everything; this only names the session on each request.
 */
@Injectable({ providedIn: 'root' })
export class ImpersonationService {
  private readonly api = inject(ApiService);
  private readonly current = signal<ImpersonationSession | null>(read());
  private timer: ReturnType<typeof setTimeout> | null = null;

  readonly session = this.current.asReadonly();
  readonly active = computed(() => this.current() !== null);

  constructor() {
    this.schedule(this.current());
    inject(DestroyRef).onDestroy(() => this.clearTimer());
  }

  /** Starts a session as `subjectId` and works in it. */
  start(subjectId: string, mode: 'view' | 'act', reason: string, subjectLabel?: string): Observable<ImpersonationSession> {
    return this.api.post<ImpersonationSession>(IMPERSONATION_ROUTES, { subject_id: subjectId, mode, reason }).pipe(
      tap(session => this.set({ ...session, subject_label: subjectLabel })),
    );
  }

  /** Ends the session on the server, then here. */
  end(): Observable<void> {
    const id = this.current()?.id;
    this.set(null);
    if (!id) return new Observable<void>(o => { o.next(); o.complete(); });
    return this.api.delete(`${IMPERSONATION_ROUTES}/${id}`);
  }

  /** Forgets the session here only (the server already ended it). */
  forget(): void {
    this.set(null);
  }

  private set(session: ImpersonationSession | null): void {
    this.current.set(session);
    write(session);
    this.schedule(session);
  }

  private schedule(session: ImpersonationSession | null): void {
    this.clearTimer();
    if (!session) return;
    const left = Date.parse(session.expires_at) - Date.now();
    if (!(left > 0)) {
      this.current.set(null);
      write(null);
      return;
    }
    this.timer = setTimeout(() => this.forget(), left);
  }

  private clearTimer(): void {
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
  }
}

function read(): ImpersonationSession | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) as ImpersonationSession : null;
  } catch {
    return null;
  }
}

function write(session: ImpersonationSession | null): void {
  try {
    if (session) sessionStorage.setItem(STORAGE_KEY, JSON.stringify(session));
    else sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // Storage blocked: the session lasts until the page reloads.
  }
}

/**
 * Q13-T2: names the live session on every API request except the session
 * routes, and forgets it when the server answers `impersonation_ended`.
 */
export const impersonationInterceptor: HttpInterceptorFn = (req, next) => {
  const config = inject(ATTOME_CONFIG);
  const impersonation = inject(ImpersonationService);
  const session = impersonation.session();
  const path = req.url.startsWith(config.apiUrl) ? req.url.slice(config.apiUrl.length) : req.url;
  if (!session || !path.startsWith('/api/v1/') || path.startsWith(IMPERSONATION_ROUTES)) {
    return next(req);
  }
  return next(req.clone({ setHeaders: { [IMPERSONATION_HEADER]: session.id } })).pipe(
    catchError((error: unknown) => {
      if (error instanceof HttpErrorResponse && endedMessage(error)) impersonation.forget();
      return throwError(() => error);
    }),
  );
};

function endedMessage(error: HttpErrorResponse): boolean {
  const body = error.error as { error?: string; message?: string } | null;
  const text = `${body?.error ?? ''} ${body?.message ?? ''}`;
  return error.status === 422 && text.includes('impersonation_ended');
}
