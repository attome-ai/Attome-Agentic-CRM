import { inject } from '@angular/core';
import { concatMap, type Observable } from 'rxjs';
import { ApiService, AuthService } from '@attome/base';
import type { SelectionAction } from '@attome/xrm/core/entity';

/**
 * Account state (`is_active`) as read off a selected `user_account` row.
 *
 * `is_active` is nullable with no default on this table (see
 * `0024_partial_unique_soft_delete.sql`'s note on legacy rows), and every
 * server-side predicate spells the live test `is_active IS NULL OR is_active
 * = TRUE`. A NULL therefore means *active*, not "unknown" — matching that
 * here keeps the toolbar from offering Activate on an account the backend
 * already considers enabled.
 *
 * A row whose view does not select the column at all is genuinely unknown,
 * and is reported as such so the caller can disable rather than guess.
 */
type AccountState = 'active' | 'inactive' | 'unknown';

function accountState(row: Record<string, unknown>): AccountState {
  if (!('is_active' in row)) return 'unknown';
  const value = row['is_active'];
  if (value === null || value === undefined) return 'active';
  if (typeof value === 'boolean') return value ? 'active' : 'inactive';
  const text = String(value).toLowerCase().trim();
  if (text === 'true'  || text === '1' || text === 't' || text === 'yes') return 'active';
  if (text === 'false' || text === '0' || text === 'f' || text === 'no')  return 'inactive';
  return 'unknown';
}

function allAre(rows: Record<string, unknown>[], state: AccountState): boolean {
  return rows.length > 0 && rows.every(r => accountState(r) === state);
}

function someAre(rows: Record<string, unknown>[], state: AccountState): boolean {
  return rows.some(r => accountState(r) === state);
}

function rowId(row: Record<string, unknown>): string | null {
  const id = row['id'];
  return typeof id === 'string' && id.length > 0 ? id : null;
}

/**
 * The users grid's replacement for the stock "Delete selected", plus a Delete
 * that is safe to offer on an account.
 *
 * `DELETE /api/v1/user_account/{id}` and `…/disable` write the same
 * `is_active` column, but they are not the same operation. Generic entity
 * delete flips the flag, applies the entity's lookup `on_target_delete`
 * policy to dependents, and writes a `SoftDelete` audit event. `…/disable`
 * bumps the account's `auth_epoch`, revokes every refresh token it holds,
 * invalidates the cached SecurityContext on every node, and deactivates every
 * API key the user owns — one transaction, D-121. Deleting a user through the
 * generic path *alone* therefore produces an account that cannot log in but
 * whose API keys keep authenticating indefinitely, which is why
 * `provide-xrm-forms.ts` still sets `hideDeleteAction` and the Delete offered
 * here runs both halves rather than the stock button's one.
 *
 * Order is load-bearing: delete first, disable second. `delete_record` (and
 * `require_record_access` beneath it) filters `is_active = true`, so a DELETE
 * issued after the disable would 404. `set_user_active` has no such filter —
 * it writes `is_active = $1` unconditionally — so running it against the
 * just-soft-deleted row still performs the revocation. `concatMap` (not
 * `mergeMap`) keeps that ordering, and short-circuits the disable if the
 * delete itself fails, so a delete refused by a `Restrict`-mode dependent
 * does not silently revoke the account anyway.
 *
 * Deliberately calls `ApiService` rather than `SecurityAdminService`:
 * `provide-xrm-forms.ts` is imported from the xrm route tree's eager
 * `providers:` array, so a static import of `@attome/xrm/security` would pull
 * that entry point's eight admin components into the chunk every `/xrm/*`
 * route downloads — the regression provide-xrm-forms.ts's own comment
 * records (main chunk 847kB -> 360kB). Two URLs are cheaper than that.
 *
 * Visibility rules, per the "don't guess intent" requirement: an action shows
 * when at least one selected account is in the state it acts on, and enables
 * only when *every* selected account is. A mixed selection therefore renders
 * both buttons, both disabled.
 */
export function userAccountStateActions(): SelectionAction[] {
  const api  = inject(ApiService);
  const auth = inject(AuthService);
  const post = (id: string, verb: 'disable' | 'enable'): Observable<void> =>
    api.post<void>(`/api/v1/admin/security/users/${id}/${verb}`, {});

  /**
   * True when the selection contains the signed-in admin's own account.
   *
   * `set_user_active` refuses `target_user_id == ctx.user_id` outright ("cannot
   * disable your own account"), and that refusal lands on the *second* leg of
   * Delete — after the soft delete has already committed. Blocking the button
   * is what keeps that from leaving an admin's own row deleted-but-not-revoked
   * with only a partial-failure alert to explain it. Deactivate does not need
   * the same guard: its single call fails atomically with nothing written.
   */
  const includesSelf = (rows: Record<string, unknown>[]): boolean => {
    const self = auth.userId();
    return self !== null && rows.some(r => rowId(r) === self);
  };

  return [
    {
      key:        'user-deactivate',
      labelKey:   'entityList.deactivateSelected',
      style:      'danger',
      confirmKey: 'entityList.deactivateConfirm',
      isVisible:  rows => someAre(rows, 'active'),
      isEnabled:  rows => allAre(rows, 'active'),
      run:        id => post(id, 'disable'),
    },
    {
      key:        'user-activate',
      labelKey:   'entityList.activateSelected',
      style:      'primary',
      confirmKey: 'entityList.activateConfirm',
      isVisible:  rows => someAre(rows, 'inactive'),
      isEnabled:  rows => allAre(rows, 'inactive'),
      run:        id => post(id, 'enable'),
    },
    {
      // Last in the array so it renders to the right of Deactivate/Activate,
      // where the stock Delete used to sit.
      key:        'user-delete',
      labelKey:   'entityList.deleteSelected',
      style:      'danger',
      confirmKey: 'entityList.deleteUserConfirm',
      // Gated on *active* for the same reason the order above is fixed: the
      // server's delete only sees live rows. An already-inactive account is
      // already `is_active = false` — the flag delete would set — so hiding
      // Delete on the inactive views costs nothing a re-run could recover.
      isVisible:  rows => someAre(rows, 'active'),
      isEnabled:  rows => allAre(rows, 'active') && !includesSelf(rows),
      run:        id => api.delete(`/api/v1/user_account/${id}`)
        .pipe(concatMap(() => post(id, 'disable'))),
    },
  ];
}
