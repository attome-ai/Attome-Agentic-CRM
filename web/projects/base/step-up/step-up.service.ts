import { Injectable, InjectionToken, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { EMPTY, Observable, catchError, defer, forkJoin, from, of, switchMap, throwError } from 'rxjs';
import { ApiService, AuthService, ATTOME_CONFIG, PASSKEY_BROWSER, isPasskeyCancelled, isSafeReturnUrl } from '@attome/base';
import type { ApiError, IdentityLinkInfo, OidcProviderInfo, StepUpChallenge, StepUpElevation, StepUpStatus, StepUpVerifyRequest } from '@attome/base';

/**
 * The factors answered in the prompt itself, through the verify route. The
 * runtime list and the type are one source of truth, so
 * catalog-coverage.spec.ts can require a `stepUp.factor.*` entry for each of
 * them (NGB-3.5).
 */
export const STEP_UP_LOCAL_FACTORS = ['password', 'totp', 'recovery_code'] as const;

export type StepUpLocalFactor = (typeof STEP_UP_LOCAL_FACTORS)[number];

/** One linked OIDC provider the caller can re-authenticate at. */
export interface StepUpProvider {
  key:         string;
  displayName: string;
  protocol:    'oidc';
}

/**
 * What the page should re-offer after a federated step-up's full page load.
 * Navigation state only: flat, primitive fields, never a credential or a
 * request body to replay.
 */
export interface StepUpPendingAction {
  kind: string;
  [field: string]: string | number | boolean | null;
}

/** Stored in `sessionStorage` across the federated redirect. */
export interface StepUpPending {
  operation:      string;
  returnUrl:      string;
  pendingAction?: StepUpPendingAction;
}

export interface StepUpPendingOptions {
  /** Same-origin relative path to come back to; defaults to the current route. */
  returnUrl?:     string;
  pendingAction?: StepUpPendingAction;
}

/** What `StepUpPromptComponent` renders. `error` is a translation key, never server text. */
export interface StepUpPromptState {
  readonly id:                 number;
  readonly operation:          string;
  readonly localFactors:       readonly StepUpLocalFactor[];
  readonly federated:          boolean;
  /** Q6-T1: the account has a passkey and this browser can use it. */
  readonly passkey:            boolean;
  readonly enrollmentRequired: boolean;
  readonly providers:          readonly StepUpProvider[];
  readonly providersLoading:   boolean;
  readonly busy:               boolean;
  readonly error:              string | null;
}

/**
 * The browser navigation to a federated step-up start. A token so tests (and
 * any embedding host) replace the real `window.location` assignment.
 */
export const STEP_UP_NAVIGATE = new InjectionToken<(url: string) => void>('STEP_UP_NAVIGATE', {
  providedIn: 'root',
  factory: () => (url: string) => { window.location.href = url; },
});

/**
 * Pre-namespacing key (NGB-1.6). Read *once* so a federated step-up that
 * started before this change still finds its pending state on return; nothing
 * writes it any more.
 */
const LEGACY_PENDING_STORAGE_KEY = 'attome-step-up-pending';

// NGB-1.3: `isSafeReturnUrl` moved to `../return-url`, beside
// `consumeReturnUrl` — the one sanctioned reader of `?returnUrl=`. Re-exported
// here because it has been part of this module's public surface since D-510.
export { isSafeReturnUrl } from '@attome/base';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isReauthRequiredFor(err: unknown, operation: string): err is ApiError {
  if (!isRecord(err) || err['kind'] !== 'reauth_required') return false;
  const op = err['operation'];
  return op === undefined || op === operation;
}

/**
 * D-510 step-up UX (rules 6 and 9, plan step 2.1d). The server alone decides
 * elevation; this service only asks for it and prompts.
 *
 * - `run` wraps a guarded request: on `reauth_required` for its operation it
 *   opens the prompt and, once verified, retries the request exactly once.
 *   Cancel or failure errors with the original `ApiError`, so the operation is
 *   not performed. The retry is outside the `catchError`, so it never loops.
 * - `elevate` opens the prompt directly (identity linking pre-checks through
 *   `status` because its start is a browser navigation).
 *
 * Signal-based like `DialogService`: `prompt` is rendered by the one
 * `StepUpPromptComponent` mounted in the host app.
 */
@Injectable({ providedIn: 'root' })
export class StepUpService {
  private readonly api      = inject(ApiService);
  private readonly auth     = inject(AuthService);
  private readonly router   = inject(Router);
  private readonly config   = inject(ATTOME_CONFIG);
  private readonly navigate = inject(STEP_UP_NAVIGATE);
  private readonly passkeys = inject(PASSKEY_BROWSER);

  private readonly promptSignal = signal<StepUpPromptState | null>(null);
  readonly prompt = this.promptSignal.asReadonly();

  private resolvePrompt: ((verified: boolean) => void) | null = null;
  private pending: StepUpPendingOptions | undefined;
  // Bumped whenever a prompt opens or closes, so a late response for a prompt
  // that was cancelled or replaced can never resolve the current one.
  private generation = 0;

  /** Whether the caller's own session could perform `operation` right now. */
  status(operation: string): Observable<StepUpStatus> {
    return this.api.get<StepUpStatus>(`/api/v1/auth/step-up/${encodeURIComponent(operation)}`);
  }

  run<T>(operation: string, request: () => Observable<T>, pending?: StepUpPendingOptions): Observable<T> {
    return defer(request).pipe(
      catchError((err: unknown) => {
        if (!isReauthRequiredFor(err, operation)) return throwError(() => err);
        return from(this.elevate(operation, err.acceptableFactors ?? [], pending)).pipe(
          switchMap(verified => (verified ? request() : throwError(() => err))),
        );
      }),
    );
  }

  /** Opens the prompt; resolves `true` once verified, `false` when cancelled. */
  elevate(operation: string, acceptableFactors: readonly string[], pending?: StepUpPendingOptions): Promise<boolean> {
    // A prompt already open is cancelled, never left dangling.
    this.finish(false);

    const localFactors = acceptableFactors.filter(
      (f): f is StepUpLocalFactor => (STEP_UP_LOCAL_FACTORS as readonly string[]).includes(f),
    );
    const passkeyOffered = acceptableFactors.includes('passkey') && this.passkeys.supported();
    const enrollmentRequired = acceptableFactors.includes('totp_enrollment_required')
      || (localFactors.length === 0 && !acceptableFactors.includes('federated') && !passkeyOffered);
    const federated = !enrollmentRequired && acceptableFactors.includes('federated');

    return new Promise<boolean>(resolve => {
      const id = ++this.generation;
      this.resolvePrompt = resolve;
      this.pending = pending;
      this.promptSignal.set({
        id,
        operation,
        localFactors:     enrollmentRequired ? [] : localFactors,
        federated,
        passkey:          !enrollmentRequired && passkeyOffered,
        enrollmentRequired,
        providers:        [],
        providersLoading: federated,
        busy:             false,
        error:            null,
      });
      if (federated) this.loadProviders(id);
    });
  }

  /** Starts a fresh challenge and verifies it with `credential`. */
  submit(factor: StepUpLocalFactor, credential: string): void {
    const state = this.promptSignal();
    if (!state || state.busy || !state.localFactors.includes(factor) || credential.length === 0) return;
    const id = state.id;
    const operation = encodeURIComponent(state.operation);
    this.patch({ busy: true, error: null });

    // Every attempt starts its own challenge: a refused verify may have spent
    // the previous one, and the server never says which.
    this.api.post<StepUpChallenge>(`/api/v1/auth/step-up/${operation}`, {}).pipe(
      switchMap(challenge => {
        // Cancelled while the challenge was starting: send no credential.
        if (!this.isCurrent(id)) return EMPTY;
        const body: StepUpVerifyRequest = { challenge_id: challenge.challenge_id, factor, credential };
        return this.api.post<StepUpElevation>(`/api/v1/auth/step-up/${operation}/verify`, body);
      }),
    ).subscribe({
      next:  () => { if (this.isCurrent(id)) this.finish(true); },
      error: (err: unknown) => { if (this.isCurrent(id)) this.onFailure(err); },
    });
  }

  /**
   * Q6-T1: answers the step-up with a passkey: the server's request options,
   * the browser's assertion, then the verify route. A cancelled browser
   * prompt leaves the step-up prompt open with no error.
   */
  submitPasskey(): void {
    const state = this.promptSignal();
    if (!state || state.busy || !state.passkey) return;
    const id = state.id;
    const operation = encodeURIComponent(state.operation);
    this.patch({ busy: true, error: null });

    this.api.post<{ options: unknown }>(`/api/v1/auth/step-up/${operation}/passkey`, {}).pipe(
      switchMap(started => (this.isCurrent(id) ? from(this.passkeys.get(started.options)) : EMPTY)),
      switchMap(response => {
        if (!this.isCurrent(id)) return EMPTY;
        return this.api.post<StepUpElevation>(`/api/v1/auth/step-up/${operation}/passkey/verify`, { response });
      }),
    ).subscribe({
      next:  () => { if (this.isCurrent(id)) this.finish(true); },
      error: (err: unknown) => {
        if (!this.isCurrent(id)) return;
        if (isPasskeyCancelled(err)) this.patch({ busy: false });
        else this.onFailure(err);
      },
    });
  }

  /** Starts a challenge, stores the pending return, then leaves for the IdP. */
  startFederated(provider: StepUpProvider): void {
    const state = this.promptSignal();
    if (!state || state.busy || !state.federated) return;
    if (!state.providers.some(p => p.key === provider.key && p.protocol === provider.protocol)) return;
    const id = state.id;
    const operation = state.operation;
    const pending = this.pending;
    this.patch({ busy: true, error: null });

    this.api.post<StepUpChallenge>(`/api/v1/auth/step-up/${encodeURIComponent(operation)}`, {}).subscribe({
      next: challenge => {
        if (!this.isCurrent(id)) return;
        const returnUrl = [pending?.returnUrl, this.router.url].find(isSafeReturnUrl) ?? '/';
        this.storePending({ operation, returnUrl, pendingAction: pending?.pendingAction });
        this.navigate(
          `${this.config.apiUrl}/api/v1/auth/step-up/${encodeURIComponent(operation)}`
          + `/${provider.protocol}/${encodeURIComponent(provider.key)}`
          + `?challenge_id=${encodeURIComponent(challenge.challenge_id)}`,
        );
        // The prompt stays busy: the page is being replaced.
      },
      error: (err: unknown) => { if (this.isCurrent(id)) this.onFailure(err); },
    });
  }

  cancel(): void {
    this.finish(false);
  }

  /**
   * Reads and clears the state stored before a federated redirect. Returns
   * `null` when there is none, when storage is unavailable, or when it fails
   * validation (including an unsafe `returnUrl`).
   */
  consumePendingReturn(): StepUpPending | null {
    let raw: string | null;
    try {
      raw = sessionStorage.getItem(this.pendingKey);
      sessionStorage.removeItem(this.pendingKey);
      if (raw === null && this.pendingKey !== LEGACY_PENDING_STORAGE_KEY) {
        raw = sessionStorage.getItem(LEGACY_PENDING_STORAGE_KEY);
        sessionStorage.removeItem(LEGACY_PENDING_STORAGE_KEY);
      }
    } catch {
      return null;
    }
    if (!raw) return null;

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return null;
    }
    if (!isRecord(parsed) || typeof parsed['operation'] !== 'string' || !isSafeReturnUrl(parsed['returnUrl'])) {
      return null;
    }

    const result: StepUpPending = { operation: parsed['operation'], returnUrl: parsed['returnUrl'] };
    const action = parsed['pendingAction'];
    if (isRecord(action) && typeof action['kind'] === 'string') {
      const pendingAction: StepUpPendingAction = { kind: action['kind'] };
      for (const [field, value] of Object.entries(action)) {
        if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) {
          pendingAction[field] = value as string | number | boolean | null;
        }
      }
      result.pendingAction = pendingAction;
    }
    return result;
  }

  // ── Private ───────────────────────────────────────────────────────────────

  private isCurrent(id: number): boolean {
    return this.promptSignal()?.id === id;
  }

  private patch(changes: Partial<StepUpPromptState>): void {
    const state = this.promptSignal();
    if (state) this.promptSignal.set({ ...state, ...changes });
  }

  private finish(verified: boolean): void {
    const resolve = this.resolvePrompt;
    this.resolvePrompt = null;
    this.pending = undefined;
    this.generation++;
    this.promptSignal.set(null);
    resolve?.(verified);
  }

  /**
   * One generic message for every refusal: the server answers a wrong
   * credential, a spent challenge and an unknown account the same way, and the
   * prompt must not imply more than that.
   */
  private onFailure(err: unknown): void {
    const e = isRecord(err) ? (err as Partial<ApiError>) : {};
    if (e.kind === 'reauth_required' && e.acceptableFactors?.includes('totp_enrollment_required')) {
      this.patch({
        busy: false, error: null, enrollmentRequired: true,
        localFactors: [], federated: false, passkey: false, providers: [], providersLoading: false,
      });
      return;
    }
    this.patch({ busy: false, error: e.status === 429 ? 'stepUp.tooManyAttempts' : 'stepUp.failed' });
  }

  private loadProviders(id: number): void {
    forkJoin({
      links: this.auth.getIdentityLinks().pipe(catchError(() => of<IdentityLinkInfo[]>([]))),
      oidc:  this.auth.getOidcProviders().pipe(catchError(() => of<OidcProviderInfo[]>([]))),
    }).subscribe(({ links, oidc }) => {
      if (!this.isCurrent(id)) return;
      // `google` is the synthetic link entry; Google has no step-up flow.
      const linked = new Set(links.map(l => l.provider_key).filter(k => k !== 'google'));
      const providers: StepUpProvider[] = [
        ...oidc.filter(p => linked.has(p.key))
          .map(p => ({ key: p.key, displayName: p.display_name, protocol: 'oidc' as const })),
      ];
      this.patch({ providers, providersLoading: false });
    });
  }

  /**
   * NGB-1.6 — namespaced by `portalKey` like every other base-owned storage key,
   * so two portals sharing one origin never consume each other's federated
   * step-up return.
   */
  private get pendingKey(): string {
    return `${this.config.portalKey ?? 'attome'}-step-up-pending`;
  }

  private storePending(pending: StepUpPending): void {
    try {
      sessionStorage.setItem(this.pendingKey, JSON.stringify(pending));
      if (this.pendingKey !== LEGACY_PENDING_STORAGE_KEY) {
        sessionStorage.removeItem(LEGACY_PENDING_STORAGE_KEY);
      }
    } catch {
      // Storage unavailable: the IdP still returns to the settings page, only
      // the re-offered action is lost. Never a reason to skip the step-up.
    }
  }
}
