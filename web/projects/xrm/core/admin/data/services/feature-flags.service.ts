import { inject, Injectable, signal } from '@angular/core';
import { Observable } from 'rxjs';
import { map, tap } from 'rxjs/operators';
import { ApiService } from '@attome/base';

/**
 * Mirrors `attome_core::FeatureFlagPolicy` (M95, D-430). Keys of
 * `user_overrides` are stringified user UUIDs; keys of `role_overrides` are
 * privilege-key strings. `percentage` (0-100) narrows `deployment: true` to a
 * deterministic hash-of-user-id rollout bucket of that size.
 */
export interface FeatureFlagPolicy {
  deployment: boolean;
  user_overrides: Record<string, boolean>;
  role_overrides: Record<string, boolean>;
  percentage: number | null;
}

/** Mirrors `attome-api::features_admin::FeatureFlagView`. */
export interface FeatureFlagView {
  key: string;
  module: string;
  description: string;
  default: boolean;
  requires: string[];
  policy: FeatureFlagPolicy;
}

export interface FeatureFlagListResponse {
  items: FeatureFlagView[];
}

export interface EffectiveFeaturesResponse {
  flags: Record<string, boolean>;
}

/**
 * The M95/D-430 feature-flag client: `GET /api/v1/features` for the calling
 * user's effective flags (what `FeatureFlagDirective` reads), plus the
 * `GET|PUT /api/v1/admin/features(/{key})` admin surface Module Management's
 * Feature Flags page drives.
 *
 * The invariant this whole feature rests on — a flag can never make
 * something reachable that the deployment's licence already hides — is
 * enforced server-side (`attome_core::feature_flag_store::is_on`). This
 * service and its directive are a *rendering* convenience only: hiding a
 * piece of UI behind an off flag is not itself a security boundary, and any
 * route or data the flag guards must still be independently license/authz
 * gated the way every other route already is.
 */
@Injectable({ providedIn: 'root' })
export class FeatureFlagsService {
  private readonly api = inject(ApiService);

  private readonly _flags = signal<Record<string, boolean>>({});
  private loaded = false;
  private inFlight: Observable<Record<string, boolean>> | null = null;

  /** The last-fetched effective-flags snapshot for the current user. */
  readonly flags = this._flags.asReadonly();

  /** Re-fetches `/api/v1/features` and updates the signal every consumer
   * (including `FeatureFlagDirective`) reads from. Call after an admin
   * changes a flag to refresh without a full page reload; the initial fetch
   * otherwise happens lazily via `ensureLoaded()`. */
  refresh(): Observable<Record<string, boolean>> {
    const request = this.api.get<EffectiveFeaturesResponse>('/api/v1/features').pipe(
      tap(res => { this._flags.set(res.flags); this.loaded = true; this.inFlight = null; }),
      map(res => res.flags),
    );
    this.inFlight = request;
    return request;
  }

  /** Triggers the first fetch if one hasn't happened yet (idempotent — safe
   * to call from every `FeatureFlagDirective` instance on a page without
   * issuing a request per instance). */
  ensureLoaded(): void {
    if (this.loaded || this.inFlight) return;
    this.refresh().subscribe({ error: () => { /* swallowed — isOn() stays false, the safe default */ } });
  }

  /** Synchronous check against the last-fetched snapshot. Returns `false`
   * (the safe default, matching the backend's own "unknown key is off, not
   * an error" posture) before the first successful fetch completes. */
  isOn(key: string): boolean {
    return this._flags()[key] === true;
  }

  // ── Admin surface (Module Management > Feature Flags) ────────────────────

  listAdmin(): Observable<FeatureFlagListResponse> {
    return this.api.get<FeatureFlagListResponse>('/api/v1/admin/features');
  }

  putAdmin(key: string, policy: FeatureFlagPolicy): Observable<FeatureFlagView> {
    return this.api.put<FeatureFlagView>(`/api/v1/admin/features/${encodeURIComponent(key)}`, policy);
  }
}
