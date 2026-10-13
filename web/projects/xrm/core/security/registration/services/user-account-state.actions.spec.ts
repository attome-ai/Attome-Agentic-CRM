import { TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiService, AuthService } from '@attome/base';
import type { SelectionAction } from '@attome/xrm/core/entity';
import { userAccountStateActions } from './user-account-state.actions';

describe('user account-state selection actions', () => {
  const post   = vi.fn(() => of(undefined));
  const del    = vi.fn(() => of(undefined));
  /** The signed-in admin, for the self-delete guard. */
  const SELF   = 'admin-self';
  let deactivate: SelectionAction;
  let activate: SelectionAction;
  let remove: SelectionAction;

  const active   = { id: 'u-1', is_active: true };
  const inactive = { id: 'u-2', is_active: false };
  /** Legacy row: nullable column, no default — migration 0024. */
  const legacy   = { id: 'u-3', is_active: null };
  /** A view that does not select the column at all. */
  const opaque   = { id: 'u-4', user_name: 'avery.marchetti' };

  beforeEach(() => {
    // Reset, not just clear: the ordering test below installs its own
    // implementations, and `mockClear` would leave those in place for every
    // test that runs after it.
    post.mockReset().mockImplementation(() => of(undefined));
    del.mockReset().mockImplementation(() => of(undefined));
    TestBed.configureTestingModule({
      providers: [
        { provide: ApiService,  useValue: { post, delete: del } },
        { provide: AuthService, useValue: { userId: () => SELF } },
      ],
    });
    const actions = TestBed.runInInjectionContext(() => userAccountStateActions());
    [deactivate, activate, remove] = actions;
  });

  it('offers Deactivate, Activate, and Delete', () => {
    expect(deactivate.key).toBe('user-deactivate');
    expect(activate.key).toBe('user-activate');
    expect(remove.key).toBe('user-delete');
  });

  it('treats a NULL is_active as active, matching the server predicate', () => {
    // Every backend live-test spells this `is_active IS NULL OR is_active =
    // TRUE`. Reading NULL as "inactive" here would offer Activate on an
    // account the server already considers enabled.
    expect(deactivate.isVisible?.([legacy])).toBe(true);
    expect(deactivate.isEnabled?.([legacy])).toBe(true);
    expect(activate.isVisible?.([legacy])).toBe(false);
  });

  it('shows only Deactivate when every selected account is active', () => {
    const rows = [active, legacy];
    expect(deactivate.isVisible?.(rows)).toBe(true);
    expect(deactivate.isEnabled?.(rows)).toBe(true);
    expect(activate.isVisible?.(rows)).toBe(false);
  });

  it('shows only Activate when every selected account is inactive', () => {
    const rows = [inactive, inactive];
    expect(activate.isVisible?.(rows)).toBe(true);
    expect(activate.isEnabled?.(rows)).toBe(true);
    expect(deactivate.isVisible?.(rows)).toBe(false);
  });

  it('shows both disabled on a mixed selection rather than guessing intent', () => {
    const rows = [active, inactive];
    expect(deactivate.isVisible?.(rows)).toBe(true);
    expect(activate.isVisible?.(rows)).toBe(true);
    expect(deactivate.isEnabled?.(rows)).toBe(false);
    expect(activate.isEnabled?.(rows)).toBe(false);
  });

  it('disables both when the view does not expose is_active', () => {
    // Unknown state is not a licence to act — neither action can claim the
    // selection is uniformly in the state it operates on.
    const rows = [opaque, opaque];
    expect(deactivate.isEnabled?.(rows)).toBe(false);
    expect(activate.isEnabled?.(rows)).toBe(false);
  });

  it('reads the string booleans query/execute returns for a bool column', () => {
    expect(deactivate.isEnabled?.([{ is_active: 'true' }])).toBe(true);
    expect(activate.isEnabled?.([{ is_active: 'false' }])).toBe(true);
    expect(activate.isEnabled?.([{ is_active: 'f' }])).toBe(true);
  });

  it('never treats an empty selection as uniformly active or inactive', () => {
    expect(deactivate.isEnabled?.([])).toBe(false);
    expect(activate.isEnabled?.([])).toBe(false);
  });

  it('calls the revoking security endpoints, not generic entity delete', () => {
    // The whole point of the override: generic DELETE would flip is_active
    // and leave the account's API keys authenticating.
    deactivate.run('user-1').subscribe();
    expect(post).toHaveBeenCalledWith('/api/v1/admin/security/users/user-1/disable', {});

    activate.run('user-2').subscribe();
    expect(post).toHaveBeenCalledWith('/api/v1/admin/security/users/user-2/enable', {});
  });

  describe('delete', () => {
    it('deletes first and disables second, so the DELETE still sees a live row', () => {
      // `delete_record`/`require_record_access` filter `is_active = true`; a
      // DELETE issued after the disable would 404. `set_user_active` has no
      // such filter, so it works on the just-soft-deleted row.
      const order: string[] = [];
      del.mockImplementation(() => { order.push('delete'); return of(undefined); });
      post.mockImplementation(() => { order.push('disable'); return of(undefined); });

      remove.run('user-9').subscribe();

      expect(order).toEqual(['delete', 'disable']);
      expect(del).toHaveBeenCalledWith('/api/v1/user_account/user-9');
      expect(post).toHaveBeenCalledWith('/api/v1/admin/security/users/user-9/disable', {});
    });

    it('does not revoke when the delete itself fails', () => {
      // A delete refused by a Restrict-mode dependent must leave the account
      // exactly as it was, not revoked-but-still-present. `concatMap` gives
      // this for free — the inner disable is never subscribed.
      del.mockImplementation(() => throwError(() => new Error('restrict')));
      const onError = vi.fn();

      remove.run('user-9').subscribe({ error: onError });

      expect(onError).toHaveBeenCalled();
      expect(post).not.toHaveBeenCalled();
    });

    it('applies only to live accounts', () => {
      expect(remove.isVisible?.([active, legacy])).toBe(true);
      expect(remove.isEnabled?.([active, legacy])).toBe(true);
      // Already `is_active = false` — the only flag delete would set.
      expect(remove.isVisible?.([inactive])).toBe(false);
      // Mixed and unknown selections stay shown-but-disabled, as elsewhere.
      expect(remove.isEnabled?.([active, inactive])).toBe(false);
      expect(remove.isEnabled?.([opaque])).toBe(false);
      expect(remove.isEnabled?.([])).toBe(false);
    });

    it('refuses a selection containing the signed-in admin', () => {
      // The server rejects self-disable, and that rejection lands *after* the
      // soft delete has committed — blocking the button is what keeps an
      // admin's own row from ending up deleted but not revoked.
      expect(remove.isEnabled?.([active, { id: SELF, is_active: true }])).toBe(false);
      expect(deactivate.isEnabled?.([active, { id: SELF, is_active: true }])).toBe(true);
    });

    it('warns about the irreversible revocation in its confirm prompt', () => {
      expect(remove.confirmKey).toBe('entityList.deleteUserConfirm');
      expect(remove.style).toBe('danger');
    });
  });
});
