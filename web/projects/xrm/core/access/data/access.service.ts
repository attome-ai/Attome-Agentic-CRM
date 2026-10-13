import { computed, inject, Injectable, signal } from '@angular/core';
import { ApiService, AuthService } from '@attome/base';
import { Observable, catchError, map, of, shareReplay } from 'rxjs';

/**
 * The `whoami` body this service reads. `role_ids` is D-789 §4.3 (additive):
 * every live staff role the caller holds, directly or through a team.
 * Hand-written: `SecurityContext` is not a `ToSchema` type, so the `whoami`
 * 200 response has no schema in `openapi.json` to generate this from.
 */
interface WhoAmI { is_admin: boolean; privileges: string[]; role_ids?: string[] | null }

interface AccessState {
  userId: string;
  isAdmin: boolean;
  privileges: ReadonlySet<string>;
  roleIds: readonly string[];
}

/**
 * NGB-1.2 — privilege-aware UI for the signed-in user, from
 * `GET /api/v1/admin/security/whoami`. Moved out of `@attome/base`, which must
 * hold no XRM endpoint knowledge (NGB-F2).
 *
 * Everything is keyed by `AuthService.userId()`: after a sign-out and a
 * different sign-in in the same tab, the previous user's privileges are never
 * read, and the next `ready()` fetches afresh. Presentation only — every route
 * a privilege hides is still authorised server-side.
 */
@Injectable({ providedIn: 'root' })
export class AccessService {
  private readonly api  = inject(ApiService);
  private readonly auth = inject(AuthService);

  private readonly state = signal<AccessState | null>(null);
  private inFlight: { userId: string; request: Observable<void> } | null = null;

  /** One shared `whoami` per signed-in user; emits once `hasPrivilege()` is current. */
  ready(): Observable<void> {
    const userId = this.auth.userId();
    if (!userId) {
      this.inFlight = null;
      this.state.set(null);
      return of(undefined);
    }
    if (this.inFlight?.userId !== userId) {
      this.inFlight = {
        userId,
        request: this.api.get<WhoAmI>('/api/v1/admin/security/whoami').pipe(
          map((res): AccessState => ({
            userId,
            isAdmin: res.is_admin === true,
            privileges: new Set(res.privileges ?? []),
            roleIds: Array.isArray(res.role_ids) ? [...res.role_ids] : [],
          })),
          // Fail closed: a failed lookup holds no privilege and no role.
          catchError(() => of<AccessState>({ userId, isAdmin: false, privileges: new Set<string>(), roleIds: [] })),
          map(next => {
            if (this.auth.userId() === userId) this.state.set(next);
          }),
          shareReplay(1),
        ),
      };
    }
    return this.inFlight.request;
  }

  /**
   * D-789 §5: the staff role ids the signed-in user holds (direct or through
   * a team), from `whoami`. Display only (for example "this rule applies to
   * you") — business-rule delivery and enforcement are filtered on the
   * server. Empty before `ready()` has emitted and for any other user.
   */
  readonly roleIds = computed<readonly string[]>(() => {
    const s = this.state();
    if (!s || s.userId !== this.auth.userId()) return [];
    return s.roleIds;
  });

  /**
   * `true` iff the current user is `system.admin` or holds `key` — the
   * server's `require_key` precedence. `false` before `ready()` has emitted
   * and for any user other than the one the state was fetched for.
   */
  hasPrivilege(key: string): boolean {
    const s = this.state();
    if (!s || s.userId !== this.auth.userId()) return false;
    return s.isAdmin || s.privileges.has(key);
  }
}
