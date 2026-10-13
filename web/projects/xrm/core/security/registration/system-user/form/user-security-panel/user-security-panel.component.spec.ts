import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';
import { ApiService, AuthService, LangService } from '@attome/base';
import { DialogService } from '@attome/base/dialog';
import { UserSecurityPanelComponent } from './user-security-panel.component';

// The panel replaces the form's old "Active account" switch, which was bound to
// a system-managed column the generic PATCH drops — it saved nothing. These
// assert the endpoints each control actually calls, and what the operator sees
// afterwards, against the rendered DOM.

const USER = 'user-1';
const BASE = `/api/v1/admin/security/users/${USER}`;

function preview(isActive: boolean | null) {
  return {
    user_id: USER,
    user_email: 'ada@example.com',
    is_active: isActive,
    configured: {
      direct_roles: [{ id: 'r1', name: 'Sales' }],
      teams: [{ id: 't1', name: 'EMEA', roles: [{ id: 'r2', name: 'Support' }] }],
      position: null,
      organizations: [],
    },
    effective: {
      is_admin: false, privileges: ['account.read', 'lead.read'], team_ids: ['t1'],
      accessible_org_ids: [], position_hierarchy_enabled: false, subordinate_user_ids: [],
    },
  };
}

const ROLES = [
  { id: 'r1', name: 'Sales', position_hierarchy_enabled: false },
  { id: 'r3', name: 'Auditor', position_hierarchy_enabled: false },
];
const USER_ROLES = [{ id: 'ur1', user_id: USER, role_id: 'r1', role_name: 'Sales' }];

describe('UserSecurityPanelComponent', () => {
  let api: {
    get: ReturnType<typeof vi.fn>;
    getAllPages: ReturnType<typeof vi.fn>;
    post: ReturnType<typeof vi.fn>;
    delete: ReturnType<typeof vi.fn>;
  };
  let confirm: ReturnType<typeof vi.fn>;
  let currentUser: ReturnType<typeof signal<string | null>>;

  function setup(isActive: boolean | null = true) {
    api = {
      get: vi.fn().mockReturnValue(of(preview(isActive))),
      getAllPages: vi.fn((path: string) => of(path.endsWith('/roles') && path.includes('/users/') ? USER_ROLES : ROLES)),
      post: vi.fn().mockReturnValue(of(undefined)),
      delete: vi.fn().mockReturnValue(of(undefined)),
    };
    confirm = vi.fn().mockResolvedValue(true);
    currentUser = signal<string | null>('admin-1');
    TestBed.configureTestingModule({
      imports: [UserSecurityPanelComponent],
      providers: [
        { provide: ApiService, useValue: api },
        { provide: AuthService, useValue: { userId: currentUser } },
        { provide: DialogService, useValue: { confirm } },
        // Echoes keys (and params) so assertions target structure, not a catalog.
        { provide: LangService, useValue: {
          translate: (key: string, p?: Record<string, unknown>) => p ? `${key} ${JSON.stringify(p)}` : key,
          errorText: (e: { message?: string }) => e.message ?? 'error',
          intlLocale: () => 'en-US',
        } },
      ],
    });
    const fixture = TestBed.createComponent(UserSecurityPanelComponent);
    fixture.componentRef.setInput('userId', USER);
    fixture.detectChanges();
    return fixture;
  }

  const q = (f: { nativeElement: HTMLElement }, id: string) =>
    f.nativeElement.querySelector<HTMLElement>(`[data-testid="${id}"]`);

  it('shows an active account with a Deactivate action', () => {
    const f = setup(true);
    expect(q(f, 'account-status')!.textContent).toContain('userForm.security.active');
    expect(q(f, 'toggle-active')!.textContent).toContain('userForm.security.deactivate');
  });

  it('treats a NULL is_active as active, matching the server predicate', () => {
    const f = setup(null);
    expect(q(f, 'toggle-active')!.textContent).toContain('userForm.security.deactivate');
  });

  it('deactivates through /disable (the revoking path), never the generic record save', async () => {
    const f = setup(true);
    q(f, 'toggle-active')!.click();
    await f.whenStable();
    f.detectChanges();

    expect(confirm).toHaveBeenCalledWith(expect.objectContaining({ variant: 'danger' }));
    expect(api.post).toHaveBeenCalledWith(`${BASE}/disable`, {});
    expect(q(f, 'account-status')!.textContent).toContain('userForm.security.inactive');
    expect(q(f, 'security-notice')!.textContent).toContain('userForm.security.deactivated');
  });

  it('tells the form the new state so its header can follow', async () => {
    const f = setup(true);
    const seen: boolean[] = [];
    f.componentInstance.activeChange.subscribe(v => seen.push(v));
    q(f, 'toggle-active')!.click();
    await f.whenStable();
    expect(seen).toEqual([false]);
  });

  it('does nothing when the confirmation is cancelled', async () => {
    const f = setup(true);
    confirm.mockResolvedValue(false);
    q(f, 'toggle-active')!.click();
    await f.whenStable();
    expect(api.post).not.toHaveBeenCalled();
  });

  it('activates a deactivated account through /enable', async () => {
    const f = setup(false);
    q(f, 'toggle-active')!.click();
    await f.whenStable();
    f.detectChanges();
    expect(api.post).toHaveBeenCalledWith(`${BASE}/enable`, {});
    expect(q(f, 'account-status')!.textContent).toContain('userForm.security.active');
  });

  it('will not let an admin deactivate their own account', () => {
    const f = setup(true);
    currentUser.set(USER);
    f.detectChanges();
    expect((q(f, 'toggle-active') as HTMLButtonElement).disabled).toBe(true);
    expect(q(f, 'self-note')).not.toBeNull();
  });

  it('shows the server refusal (e.g. no seat left) as an alert', async () => {
    const f = setup(false);
    api.post.mockReturnValue(throwError(() => ({ kind: 'conflict', message: 'Seat limit reached' })));
    q(f, 'toggle-active')!.click();
    await f.whenStable();
    f.detectChanges();
    const alert = q(f, 'security-error')!;
    expect(alert.getAttribute('role')).toBe('alert');
    expect(alert.textContent).toContain('Seat limit reached');
    expect(q(f, 'account-status')!.textContent).toContain('userForm.security.inactive');
  });

  it('lists direct roles and offers only roles the user does not already hold', () => {
    const f = setup();
    expect(q(f, 'role-list')!.textContent).toContain('Sales');
    const options = Array.from(q(f, 'role-select')!.querySelectorAll('option')).map(o => o.textContent!.trim());
    expect(options).toContain('Auditor');
    expect(options).not.toContain('Sales');
  });

  it('assigns a role through the gated endpoint and refreshes access', () => {
    const f = setup();
    api.post.mockReturnValue(of({ id: 'ur2', user_id: USER, role_id: 'r3', role_name: 'Auditor', approval_pending: false }));
    f.componentInstance.selectedRoleId = 'r3';
    f.componentInstance.assignRole();
    f.detectChanges();
    expect(api.post).toHaveBeenCalledWith(`${BASE}/roles`, { role_id: 'r3' });
    expect(q(f, 'security-notice')!.textContent).toContain('userForm.security.roleAssigned');
    expect(api.get).toHaveBeenCalledTimes(2);
  });

  it('reports a four-eyes submission as pending, not as assigned', () => {
    const f = setup();
    api.post.mockReturnValue(of({ id: null, user_id: USER, role_id: 'r3', approval_pending: true, approval_request_id: 'a1' }));
    f.componentInstance.selectedRoleId = 'r3';
    f.componentInstance.assignRole();
    f.detectChanges();
    const notice = q(f, 'security-notice')!.textContent!;
    expect(notice).toContain('userForm.security.roleApprovalPending');
    expect(notice).toContain('Auditor');
    expect(api.get).toHaveBeenCalledTimes(1);
  });

  it('removes a role after confirmation', async () => {
    const f = setup();
    await f.componentInstance.removeRole(USER_ROLES[0]);
    expect(api.delete).toHaveBeenCalledWith(`${BASE}/roles/r1`);
  });

  it('reports "nothing to reset" when the user has no MFA enrollment', async () => {
    const f = setup();
    api.post.mockReturnValue(throwError(() => ({ kind: 'not_found', message: '' })));
    q(f, 'reset-mfa')!.click();
    await f.whenStable();
    f.detectChanges();
    expect(api.post).toHaveBeenCalledWith(`${BASE}/mfa/reset`, {});
    expect(q(f, 'security-notice')!.textContent).toContain('userForm.security.noMfa');
    expect(q(f, 'security-error')).toBeNull();
  });

  it('re-reads effective access on Refresh (grid changes beside it emit nothing)', () => {
    const f = setup();
    q(f, 'refresh-access')!.click();
    f.detectChanges();
    expect(api.get).toHaveBeenCalledTimes(2);
    expect((q(f, 'refresh-access') as HTMLButtonElement).disabled).toBe(false);
  });

  it('shows the effective privilege count', () => {
    const f = setup();
    expect(q(f, 'privilege-summary')!.textContent).toContain('"count":2');
  });

  it('shows "never" when the user has not signed in', () => {
    const f = setup();
    expect(q(f, 'last-login')!.textContent).toContain('userForm.security.never');
  });
});
